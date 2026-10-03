"""Distributor-side registry. Holds PUBLIC keys and document hashes only."""
import json, os, uuid
from . import crypto as C

class Registry:
    def __init__(self, path=None):
        self.path = path
        self.d = {"recipients": {}, "documents": {}}
        if path and os.path.exists(path): self.d = json.load(open(path))

    def _save(self):
        if self.path: json.dump(self.d, open(self.path, "w"), indent=1)

    def add_recipient(self, user_id, display_name, kem_pk_b64, dsa_pk_b64) -> str:
        kid = C.key_id(C.b64d(kem_pk_b64), C.b64d(dsa_pk_b64))
        self.d["recipients"][kid] = {"user_id": user_id, "display_name": display_name, "kem_pk": kem_pk_b64,
                                     "dsa_pk": dsa_pk_b64, "status": "active"}
        self._save(); return kid

    def revoke(self, kid): self.d["recipients"][kid]["status"] = "revoked"; self._save()
    def recipient(self, kid): return self.d["recipients"].get(kid)
    def dsa_pk(self, kid):
        r = self.recipient(kid); return C.b64d(r["dsa_pk"]) if r else None

    def add_document(self, title, original_hash, owner) -> str:
        did = "D-" + uuid.uuid4().hex[:8]
        self.d["documents"][did] = {"title": title, "original_hash": original_hash, "owner": owner, "status": "active"}
        self._save(); return did
    def document(self, did): return self.d["documents"].get(did)
