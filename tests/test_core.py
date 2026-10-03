import json, pytest
from tracevault import crypto as C, package, events
from tracevault.keystore import KeyStore
from tracevault.release import decrypt_and_release, ReleaseDenied
from tracevault import watermark as W

def test_kem_dsa_roundtrip_and_tamper():
    pk, sk = C.dsa_keygen(); s = C.dsa_sign(sk, b"m")
    assert C.dsa_verify(pk, b"m", s) and not C.dsa_verify(pk, b"x", s) and not C.dsa_verify(pk, b"m", s[:-1] + bytes([s[-1] ^ 1]))
    kp, ks = C.kem_keygen(); ct, ss = C.kem_encaps(kp); assert C.kem_decaps(ks, ct) == ss

def test_envelope_three_recipients_distinct_encaps(world):
    w = world; e = w["pkg"]["recipients"]
    assert len({v["kem_ct"] for v in e.values()}) == 3
    for k, ks in zip(w["kids"], w["ks"]): assert package.open_package(w["pkg"], k, ks) == w["pdf"]

def test_wrong_and_unauthorized_recipient(world):
    w = world; sub = package.for_recipient(w["pkg"], w["kids"][0])
    with pytest.raises(PermissionError): package.open_package(sub, w["kids"][1], w["ks"][1])
    with pytest.raises(Exception): package.open_package(sub, w["kids"][0], w["ks"][1])  # wrong private key

def test_keystore_wrong_passphrase_and_no_private_key_in_file(tmp_path):
    k = KeyStore.create(str(tmp_path / "k"), "right")
    with pytest.raises(PermissionError): k.unlock("wrong")
    raw = open(tmp_path / "k").read(); assert "kem_sk" not in raw and "dsa_sk" not in raw
    with pytest.raises(PermissionError): k.sign(b"x")   # locked

def test_release_commits_and_events_are_distinct(world):
    w = world; steps = []
    r1 = decrypt_and_release(w["pkg"], w["ks"][1], w["ledger"], w["reg"], lambda s, st: steps.append((s, st)))
    r2 = decrypt_and_release(w["pkg"], w["ks"][1], w["ledger"], w["reg"])
    assert r1.event["watermark_digest"] != r2.event["watermark_digest"] and r2.record["index"] == 1
    assert [s for s, st in steps if st == "done"] == ["decrypt", "fingerprint", "sign", "ledger", "release"]

def test_fail_closed_no_quorum(world):
    w = world
    w["ledger"].nodes[0].online = w["ledger"].nodes[1].online = False
    with pytest.raises(ReleaseDenied) as e: decrypt_and_release(w["pkg"], w["ks"][1], w["ledger"], w["reg"])
    assert e.value.step == "ledger"
    assert all(len(n.records) == 0 for n in w["ledger"].nodes)

def test_fail_closed_fingerprint_and_signature(world, monkeypatch):
    w = world
    class Boom(W.PdfProtector):
        def embed(self, *a): raise RuntimeError("embed failed")
    with pytest.raises(ReleaseDenied) as e: decrypt_and_release(w["pkg"], w["ks"][0], w["ledger"], w["reg"], protector=Boom())
    assert e.value.step == "fingerprint"
    w["ks"][0].lock()
    with pytest.raises(ReleaseDenied) as e: decrypt_and_release(w["pkg"], w["ks"][0], w["ledger"], w["reg"])
    assert e.value.step in ("decrypt", "sign")

def test_revoked_or_unregistered_signer_rejected_by_ledger(world):
    w = world; ev = events.new_event(w["did"], w["kids"][0], C.sha3(w["pdf"]))
    sig = w["ks"][1].sign(C.event_message(ev))        # signed by the wrong recipient
    with pytest.raises(RuntimeError): w["ledger"].commit(ev, sig, w["kids"][0], w["reg"])
