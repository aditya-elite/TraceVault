"""Canonical decryption event and session-bound watermark digest."""
import os, time, uuid
from . import crypto as C

EVENT_VERSION, WM_VERSION = 1, 1

def watermark_digest(document_id, recipient_key_id, session_id, nonce_hex, document_hash, wm_version=WM_VERSION) -> str:
    return C.sha3(b"TV-WM", document_id.encode(), recipient_key_id.encode(), session_id.encode(),
                  bytes.fromhex(nonce_hex), str(wm_version).encode(), document_hash.encode())

def new_event(document_id, recipient_key_id, document_hash) -> dict:
    session_id, nonce = "S-" + uuid.uuid4().hex[:12], os.urandom(16).hex()
    return {"event_version": EVENT_VERSION, "document_id": document_id, "recipient_key_id": recipient_key_id,
            "session_id": session_id, "nonce": nonce, "document_hash": document_hash,
            "watermark_digest": watermark_digest(document_id, recipient_key_id, session_id, nonce, document_hash),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "watermark_version": WM_VERSION}

def digest_matches(ev: dict) -> bool:
    return ev["watermark_digest"] == watermark_digest(ev["document_id"], ev["recipient_key_id"], ev["session_id"],
                                                      ev["nonce"], ev["document_hash"], ev["watermark_version"])
