"""Recipient-side decryption + fail-closed release gate.

Order: decapsulate -> decrypt -> fingerprint -> sign -> ledger commit -> release.
Plaintext and the protected copy exist only in memory and are returned ONLY if every mandatory step succeeded.
"""
from dataclasses import dataclass
from . import crypto as C, events, package, watermark as W

class ReleaseDenied(Exception):
    def __init__(self, step, reason):
        super().__init__(f"release denied at '{step}': {reason}"); self.step, self.reason = step, reason

@dataclass
class Released:
    protected_pdf: bytes
    event: dict
    record: dict

STEPS = ("decapsulate", "decrypt", "fingerprint", "sign", "ledger", "release")

def decrypt_and_release(pkg: dict, keystore, ledger, registry, progress=lambda step, status: None,
                        protector: W.ContentProtector | None = None) -> Released:
    def run(step, fn):
        progress(step, "running")
        try: out = fn()
        except Exception as e:
            progress(step, "failed"); raise ReleaseDenied(step, str(e)) from None
        progress(step, "done"); return out
    kid = keystore.key_id
    plaintext = run("decrypt", lambda: package.open_package(pkg, kid, keystore))   # includes ML-KEM decapsulation
    doc_hash = C.sha3(plaintext)
    event = events.new_event(pkg["document_id"], kid, doc_hash)
    protected = run("fingerprint", lambda: (protector or W.protector_for(plaintext)).embed(plaintext, W.make_payload(event["watermark_digest"])))
    del plaintext
    sig = run("sign", lambda: keystore.sign(C.event_message(event)))
    record = run("ledger", lambda: ledger.commit(event, sig, kid, registry))
    progress("release", "done")
    return Released(protected, event, record)
