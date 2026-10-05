"""Secrets come from the environment only; ledger appends are serialised by file locks."""
import glob, json, multiprocessing as mp, os, re, threading
import pytest
from tracevault import crypto as C, events
from tracevault.config import ConfigError
from tracevault.db import Database
from tracevault.keystore import KeyStore
from tracevault.ledger import Ledger, GENESIS
from tracevault.registry import Registry

ROOT = os.path.dirname(os.path.dirname(__file__))

def test_missing_secrets_fail_loudly(monkeypatch, tmp_path):
    monkeypatch.delenv("TV_MASTER_KEY")
    with pytest.raises(ConfigError, match="TV_MASTER_KEY"):
        Database(str(tmp_path / "a.db"))
    monkeypatch.delenv("TV_NODE_2_KEY")
    with pytest.raises(ConfigError, match="TV_NODE_2_KEY"):
        Ledger(str(tmp_path / "l"))

def test_malformed_secret_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("TV_MASTER_KEY", C.b64e(b"too short"))
    with pytest.raises(ConfigError):
        Database(str(tmp_path / "a.db"))

def test_no_secret_files_are_written(tmp_path, pdf):
    from tracevault.api import create_app
    create_app(str(tmp_path / "d"), {"a": {"password": "adminpass1", "role": "admin"}})
    names = {os.path.basename(p) for p in glob.glob(str(tmp_path / "d" / "**"), recursive=True)}
    assert not names & {"master.key", "api_secret.key", "node_key.json"}

def test_source_has_no_flat_file_key_loading():
    """keygen.py is the only module allowed to mention the legacy file names (it migrates them)."""
    src = "".join(open(f).read() for f in glob.glob(os.path.join(ROOT, "tracevault", "*.py"))
                  if not f.endswith("keygen.py"))
    for needle in ("master.key", "api_secret.key", "node_key.json", "alice.keys", "admin123", "bob123"):
        assert needle not in src, needle

def test_keystore_from_env_blob(tmp_path, monkeypatch):
    path = str(tmp_path / "bob.keys")
    ks = KeyStore.create(path, "pp")
    kid = ks.key_id
    monkeypatch.setenv(KeyStore.env_name("bob"), ks.export_blob())
    os.remove(path)                                  # no file on disk at all
    loaded = KeyStore.locate("bob")
    assert loaded.unlock("pp").key_id == kid
    with pytest.raises(PermissionError):
        KeyStore.locate("bob").unlock("wrong")

def test_frontend_and_server_are_decoupled():
    html = open(os.path.join(ROOT, "tracevault", "web", "index.html"), encoding="utf-8").read()
    assert not re.search(r"\b(db|ledger)\.py\b|sqlite|import\s", html)
    calls = re.findall(r"(?:fetch|api)\(\s*[`\"'](/[^`\"'$]*)", html)
    assert len(calls) >= 15, "expected the UI to call the REST API"
    assert not re.search(r"fetch\(\s*[^p]", html.replace("fetch(path", "")), "all requests must go through api()"
    for m in calls:
        assert m.startswith(("/auth/", "/submitter/", "/auditor/", "/admin/", "/recipient/", "/simulate/")), m
    server = open(os.path.join(ROOT, "tracevault", "server.py")).read()
    assert not re.search(r"^\s*(from|import)\s+.*\b(db|ledger)\b", server, re.M)

# ---------------------------------------------------------------- concurrency
def _make_signers(tmp, n):
    reg, signers = Registry(), []
    for i in range(n):
        ks = KeyStore.create(str(tmp / f"s{i}.keys"), "pw").unlock("pw"); p = ks.public
        signers.append((ks, reg.add_recipient(f"u{i}", f"R{i}", p["kem_pk"], p["dsa_pk"])))
    return reg, signers

def _commit_one(ledger, reg, ks, kid):
    ev = events.new_event("D-1", kid, C.sha3(os.urandom(8)))
    return ledger.commit(ev, ks.sign(C.event_message(ev)), kid, reg)

def _assert_consistent(path, expected):
    for i in range(1, 5):
        lines = [json.loads(l) for l in open(f"{path}/node-{i}/chain.jsonl")]
        assert len(lines) == expected, f"node-{i}: {len(lines)} != {expected}"
        prev = GENESIS
        for k, r in enumerate(lines):
            assert r["index"] == k and r["prev_hash"] == prev
            prev = r["record_hash"]

def test_threads_share_one_ledger_without_forking(tmp_path):
    reg, signers = _make_signers(tmp_path, 3)
    ledger, errors = Ledger(str(tmp_path / "l")), []
    def work(j):
        try:
            _commit_one(ledger, reg, *signers[j % 3])
        except Exception as e:
            errors.append(e)
    ts = [threading.Thread(target=work, args=(j,)) for j in range(9)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errors, errors
    _assert_consistent(tmp_path / "l", 9)
    assert Ledger(str(tmp_path / "l")).verify(reg)["ok"]

def test_independent_ledger_instances_see_each_others_commits(tmp_path):
    """Two Ledger objects on one directory (= two worker processes) must not fork the chain."""
    reg, signers = _make_signers(tmp_path, 1)
    a, b = Ledger(str(tmp_path / "l")), Ledger(str(tmp_path / "l"))
    for k in range(4):
        _commit_one(a if k % 2 == 0 else b, reg, *signers[0])
    _assert_consistent(tmp_path / "l", 4)

def _proc(base, reg_path, ks_path, n):
    from tracevault.registry import Registry
    reg = Registry(reg_path); ks = KeyStore(ks_path).unlock("pw"); led = Ledger(base)
    for _ in range(n):
        _commit_one(led, reg, ks, ks.key_id)

def test_multiple_processes_append_safely(tmp_path):
    ks = KeyStore.create(str(tmp_path / "k.keys"), "pw").unlock("pw"); p = ks.public
    reg = Registry(str(tmp_path / "reg.json")); reg.add_recipient("u", "R", p["kem_pk"], p["dsa_pk"])
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_proc, args=(str(tmp_path / "l"), str(tmp_path / "reg.json"), str(tmp_path / "k.keys"), 3)) for _ in range(3)]
    [x.start() for x in procs]; [x.join(120) for x in procs]
    assert all(x.exitcode == 0 for x in procs)
    _assert_consistent(tmp_path / "l", 9)
    assert Ledger(str(tmp_path / "l")).verify(reg)["ok"]

def test_stale_append_is_rejected(tmp_path):
    reg, signers = _make_signers(tmp_path, 1)
    led = Ledger(str(tmp_path / "l")); _commit_one(led, reg, *signers[0])
    node = led.nodes[0]
    stale = {"index": 0, "prev_hash": GENESIS, "event": {}, "signature": "", "signer_key_id": "x", "record_hash": "h"}
    with pytest.raises(ValueError, match="chain link"):
        node.append(stale)
    assert len(open(node.chain_path).readlines()) == 1
