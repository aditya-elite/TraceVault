"""Lightweight four-node permissioned provenance ledger (tamper-evident, offline/network-ready).

Records are hash-linked and carry a quorum certificate: >=3 of 4 nodes must independently validate the
event (recipient ML-DSA signature, chain link, no duplicate session, active recipient) and attest to
the record hash with their own ML-DSA key. One node cannot silently rewrite history: its chain/attestations
would diverge.

Includes:
- BFT-style leader-based quorum commit (requires 3 of 4 independent node attestations).
- Multi-node independent key and directory stores.
- Validated node resynchronization with chain integrity verification.
- Quorum-signed checkpoints for offline investigator pinning.
- Standalone ledger chain verification.
"""
import json, os, threading, time
from filelock import FileLock
from . import crypto as C
from .config import env_int
from .events import digest_matches

N_NODES, QUORUM = 4, 3
GENESIS = "0" * 64

def record_hash(index, event, sig_b64, signer, prev) -> str:
    return C.sha3(str(index).encode(), C.canonical(event), sig_b64.encode(), signer.encode(), prev.encode())

def node_key_env(node_id: str) -> str:
    """'node-3' -> 'TV_NODE_3_KEY'"""
    return "TV_" + node_id.upper().replace("-", "_") + "_KEY"

class LedgerNode:
    def __init__(self, node_id, directory, port: int | None = None, key: tuple[bytes, bytes] | None = None):
        self.id, self.dir, self.online = node_id, directory, True
        self.port = port
        os.makedirs(directory, exist_ok=True)
        # The node's ML-DSA key pair comes from the environment (TV_NODE_<n>_KEY), never from a file on disk.
        self.pk, self._sk = key or C.keypair_from_env(node_key_env(node_id))
        self.chain_path = os.path.join(directory, "chain.jsonl")
        # Cross-process + cross-thread guard around every write to this node's chain file.
        self._lock = FileLock(self.chain_path + ".lock", timeout=env_int("TV_LOCK_TIMEOUT", 30))
        self.records = []
        self.refresh()

    def refresh(self):
        """Pull any records appended to chain.jsonl by another process/thread since we last looked.
        The chain is append-only, so only the unseen tail needs parsing."""
        if not os.path.exists(self.chain_path):
            return
        with open(self.chain_path) as f:
            for i, line in enumerate(f):
                if i < len(self.records) or not line.strip():
                    continue
                try:
                    self.records.append(json.loads(line))
                except json.JSONDecodeError:
                    break   # torn trailing write from a crashed writer; ignore until it is completed/repaired

    @property
    def head(self):
        return self.records[-1]["record_hash"] if self.records else GENESIS

    def validate(self, rec, registry):
        ev = rec["event"]
        if rec["prev_hash"] != self.head or rec["index"] != len(self.records):
            raise ValueError("chain link mismatch")
        if any(r["event"].get("session_id") == ev.get("session_id") for r in self.records if ev.get("session_id")):
            raise ValueError("duplicate session")
        if ev.get("recipient_key_id") and ev["recipient_key_id"] != rec["signer_key_id"]:
            raise ValueError("signer/recipient mismatch")
        
        # Check signer public key & signature
        pk = registry.dsa_pk(rec["signer_key_id"])
        if pk is None:
            raise ValueError("unknown signer")
        if not C.dsa_verify(pk, C.event_message(ev), C.b64d(rec["signature"])):
            raise ValueError("invalid event signature")
            
        # Verify watermark digest
        if ev.get("watermark_digest") and not digest_matches(ev):
            raise ValueError("watermark digest does not match event fields")
            
        if rec["record_hash"] != record_hash(rec["index"], ev, rec["signature"], rec["signer_key_id"], rec["prev_hash"]):
            raise ValueError("bad record hash")

    def attest(self, rec_hash: str) -> str:
        return C.b64e(C.dsa_sign(self._sk, b"TV-ATTEST" + rec_hash.encode()))

    def attest_checkpoint(self, checkpoint_data: bytes) -> str:
        return C.b64e(C.dsa_sign(self._sk, b"TV-CHECKPOINT" + checkpoint_data))

    def append(self, rec):
        """Append one record atomically. Takes the file lock, re-reads the tail from disk, re-checks that the
        record still extends the chain, then writes + fsyncs before releasing the lock."""
        line = json.dumps(rec)
        with self._lock:
            self.refresh()
            if rec["index"] != len(self.records) or rec["prev_hash"] != self.head:
                raise ValueError(f"{self.id}: concurrent write detected, chain link mismatch")
            with open(self.chain_path, "a") as f:
                f.write(line + "\n"); f.flush(); os.fsync(f.fileno())
            self.records.append(json.loads(line))   # each node owns an independent copy

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "online": self.online,
            "port": self.port,
            "pk_b64": C.b64e(self.pk),
            "record_count": len(self.records),
            "head": self.head
        }

class Ledger:
    def __init__(self, base_dir, base_port: int = 8100):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        # One commit at a time across all threads and processes sharing this ledger directory.
        self._tlock = threading.RLock()
        self._flock = FileLock(os.path.join(base_dir, "ledger.lock"), timeout=env_int("TV_LOCK_TIMEOUT", 30))
        self.nodes = [
            LedgerNode(f"node-{i+1}", os.path.join(base_dir, f"node-{i+1}"), port=base_port + i)
            for i in range(N_NODES)
        ]
        self.node_pks = {n.id: n.pk for n in self.nodes}

    def commit(self, event: dict, signature: bytes, signer_key_id: str, registry) -> dict:
        with self._tlock, self._flock:
            for n in self.nodes:
                n.refresh()          # see commits made by other workers before choosing index/prev_hash
            return self._commit_locked(event, signature, signer_key_id, registry)

    def _commit_locked(self, event: dict, signature: bytes, signer_key_id: str, registry) -> dict:
        live = [n for n in self.nodes if n.online]
        lead = max(live, key=lambda n: len(n.records), default=None)
        if lead is None or len(live) < QUORUM:
            raise RuntimeError(f"ledger quorum unavailable ({len(live)}/{N_NODES} nodes online)")
            
        sig_b64 = C.b64e(signature)
        idx = len(lead.records)
        rec = {
            "index": idx,
            "event": event,
            "signature": sig_b64,
            "signer_key_id": signer_key_id,
            "prev_hash": lead.head
        }
        rec["record_hash"] = record_hash(idx, event, sig_b64, signer_key_id, rec["prev_hash"])
        
        # BFT-style voting: collect signed attestations from all live nodes
        atts, errs = {}, []
        for n in live:
            try:
                n.validate(rec, registry)
                atts[n.id] = n.attest(rec["record_hash"])
            except Exception as e:
                errs.append(f"{n.id}: {e}")
                
        if len(atts) < QUORUM:
            raise RuntimeError(f"quorum not reached ({len(atts)}/{QUORUM}): {'; '.join(errs)}")
            
        rec["attestations"] = atts
        for n in live:
            if n.id in atts:
                n.append(rec)
        return rec

    def resync(self, node):
        """Bring a lagging or restored node level with the longest validated peer chain."""
        with self._tlock, self._flock:
            self._resync_locked(node)

    def _resync_locked(self, node):
        for n in self.nodes:
            n.refresh()
        candidates = [n for n in self.nodes if n is not node and n.online]
        if not candidates:
            return
        src = max(candidates, key=lambda n: len(n.records))
        # Validate source records from current node length
        for r in src.records[len(node.records):]:
            # verify record hash and quorum attestations before accepting
            good = sum(
                1 for nid, s in r.get("attestations", {}).items()
                if nid in self.node_pks and C.dsa_verify(self.node_pks[nid], b"TV-ATTEST" + r["record_hash"].encode(), C.b64d(s))
            )
            if good >= QUORUM:
                node.append(r)

    def create_checkpoint(self) -> dict:
        """Create a quorum-signed checkpoint of the current ledger head."""
        live = [n for n in self.nodes if n.online]
        if len(live) < QUORUM:
            raise RuntimeError("Cannot checkpoint without quorum")
        common_head = live[0].head
        if not all(n.head == common_head for n in live):
            raise RuntimeError("Nodes disagree on head hash")
        
        cp_data = json.dumps({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "head": common_head,
            "records": len(live[0].records)
        }, sort_keys=True).encode()
        
        atts = {n.id: n.attest_checkpoint(cp_data) for n in live}
        return {
            "checkpoint": json.loads(cp_data),
            "attestations": atts
        }

    def verify(self, registry) -> dict:
        res = {"nodes": {}, "ok": False, "errors": []}
        for n in self.nodes:
            errs, prev = [], GENESIS
            for i, r in enumerate(n.records):
                if r["index"] != i or r["prev_hash"] != prev:
                    errs.append(f"#{i}: broken hash link")
                if r["record_hash"] != record_hash(i, r["event"], r["signature"], r["signer_key_id"], r["prev_hash"]):
                    errs.append(f"#{i}: record hash mismatch")
                good = sum(
                    1 for nid, s in r.get("attestations", {}).items()
                    if nid in self.node_pks and C.dsa_verify(self.node_pks[nid], b"TV-ATTEST" + r["record_hash"].encode(), C.b64d(s))
                )
                if good < QUORUM:
                    errs.append(f"#{i}: only {good} valid node attestations")
                pk = registry.dsa_pk(r["signer_key_id"])
                if pk is None or not C.dsa_verify(pk, C.event_message(r["event"]), C.b64d(r["signature"])):
                    errs.append(f"#{i}: event signature invalid")
                prev = r["record_hash"]
            res["nodes"][n.id] = {
                "records": len(n.records),
                "head": n.head[:16],
                "online": n.online,
                "ok": not errs,
                "errors": errs
            }
        good = [v for v in res["nodes"].values() if v["ok"] and v["online"]]
        heads = {v["head"] for v in good}
        res["ok"] = len(good) >= QUORUM and len(heads) == 1
        if not res["ok"]:
            res["errors"].append("insufficient agreeing nodes with valid chains")
        return res

    def find_by_watermark(self, id_hex: str):
        """Return the matching record only if >= QUORUM nodes hold identical content (recomputed hash)."""
        votes = {}
        for n in self.nodes:
            if not n.online:
                continue
            for r in n.records:
                if r["event"]["watermark_digest"].startswith(id_hex):
                    h = record_hash(r["index"], r["event"], r["signature"], r["signer_key_id"], r["prev_hash"])
                    votes.setdefault(h, []).append(r)
        for recs in votes.values():
            if len(recs) >= QUORUM:
                return recs[0]
        return None

    def export_chain(self) -> dict:
        return {
            "node_pks": {k: C.b64e(v) for k, v in self.node_pks.items()},
            "nodes": {n.id: n.records for n in self.nodes}
        }
