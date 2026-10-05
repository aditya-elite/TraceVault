"""Evidence intake and verification pipeline -> provenance report (never a legal conclusion)."""
import os, time
from . import crypto as C, watermark as W
from .events import digest_matches

VERIFIED = "VERIFIED"; PROOF_INCOMPLETE = "WATERMARK DETECTED — PROOF INCOMPLETE"
INVALID_SIG = "INVALID SIGNATURE"; NO_WM = "NO WATERMARK"; LOW = "CORRUPTED / LOW CONFIDENCE"
DISCLAIMER = ("This report is cryptographic provenance evidence about a decryption event. It does not "
              "determine legal responsibility, intent, or how the artifact came to be leaked.")

def process_case(data: bytes, filename: str, registry, ledger, evidence_dir: str, investigator="investigator") -> dict:
    ev_hash = C.sha3(data)
    os.makedirs(evidence_dir, exist_ok=True)
    path = os.path.join(evidence_dir, f"{ev_hash[:16]}_{os.path.basename(filename)}")
    if not os.path.exists(path):                         # original evidence is preserved, never overwritten
        with open(path, "xb") as f: f.write(data)
        os.chmod(path, 0o444)
    rep = {"case_id": "C-" + ev_hash[:10], "investigator": investigator, "evidence_file": os.path.basename(filename),
           "evidence_sha3_256": ev_hash, "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "checks": [], "disclaimer": DISCLAIMER}
    def check(name, ok, detail): rep["checks"].append({"name": name, "passed": ok, "detail": detail}); return ok
    def done(status): rep["status"] = status; return rep

    kind, imgs = W.decode_evidence(data, filename)
    if not check("Evidence readable", kind is not None, f"type={kind}"): return done(LOW)
    ex = W.extract_images_robust(imgs); rep["extraction"] = {"pages_or_images": len(imgs), "strength": ex["strength"], "result": ex["status"]}
    if ex["status"] == "none": check("Watermark extraction", False, f"no watermark energy (strength {ex['strength']})"); return done(NO_WM)
    if ex["status"] == "low": check("Watermark extraction", False, "watermark energy present but payload failed integrity check"); return done(LOW)
    wid = ex["payload"].hex(); check("Watermark extraction", True, f"id={wid} strength={ex['strength']}")

    rec = ledger.find_by_watermark(wid)
    if not check("Ledger lookup", rec is not None, "matching event found" if rec else "no ledger event for this watermark"):
        return done(PROOF_INCOMPLETE)
    e = rec["event"]; kid = e["recipient_key_id"]
    rep["match"] = {"record_index": rec["index"], "session_id": e["session_id"], "recipient_key_id": kid,
                    "recipient": (registry.recipient(kid) or {}).get("display_name"), "document_id": e["document_id"],
                    "decrypted_at": e["timestamp"], "record_hash": rec["record_hash"]}
    pk = registry.dsa_pk(kid)
    if not check("Recipient ML-DSA-65 signature", pk is not None and C.dsa_verify(pk, C.event_message(e), C.b64d(rec["signature"])),
                 "signature verifies under registered key" if pk else "signer key not registered"):
        return done(INVALID_SIG)
    ok = check("Watermark digest binds event fields", digest_matches(e), "recomputed SHA3-256 matches")
    doc = registry.document(e["document_id"])
    ok &= check("Document hash matches registered original", bool(doc) and doc["original_hash"] == e["document_hash"], "")
    lv = ledger.verify(registry); rep["ledger"] = lv
    ok &= check("Ledger integrity & quorum", lv["ok"], f"{sum(v['ok'] for v in lv['nodes'].values())}/4 nodes valid and agreeing")
    return done(VERIFIED if ok else PROOF_INCOMPLETE)

# Plain-language classification for UIs (green shield / amber / red warning). Raw statuses stay in reports.
_VERDICTS = {
    VERIFIED: ("verified", "Verified", "This file is an authentic, tracked copy and the record is intact."),
    PROOF_INCOMPLETE: ("inconclusive", "Needs review", "A tracking mark was found but the proof is incomplete. Ask an auditor to review."),
    INVALID_SIG: ("failed", "Failed", "The tracking record does not match its owner. Do not trust this file."),
    NO_WM: ("failed", "Failed", "No tracking mark found. This is not a tracked copy."),
    LOW: ("failed", "Failed", "The file is damaged, unreadable or not a supported type, so it could not be checked."),
}

def verdict(status: str) -> dict:
    kind, headline, explain = _VERDICTS.get(status, ("inconclusive", "Needs review", "Status unknown."))
    return {"verdict": kind, "headline": headline, "explain": explain}

def render_text(r: dict) -> str:
    L = [f"TRACEVAULT EVIDENCE REPORT  {r['case_id']}", f"Status: {r['status']}", f"Evidence: {r['evidence_file']}",
         f"SHA3-256: {r['evidence_sha3_256']}", ""]
    L += [f"[{'PASS' if c['passed'] else 'FAIL'}] {c['name']}: {c['detail']}" for c in r["checks"]]
    if "match" in r: L += ["", *(f"{k}: {v}" for k, v in r["match"].items())]
    return "\n".join(L + ["", r["disclaimer"]])
