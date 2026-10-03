"""Multi-recipient envelope encryption: one AES-256-GCM payload, one ML-KEM-768 encapsulation per recipient."""
import os
from . import crypto as C

VERSION = 1

def create_package(plaintext: bytes, document_id: str, title: str, recipients: dict) -> dict:
    """recipients: {recipient_key_id: kem_pk_bytes}."""
    cek = os.urandom(32)
    aad = f"TVPKG{VERSION}|{document_id}".encode()
    nonce, ct = C.aes_encrypt(cek, plaintext, aad)
    entries = {}
    for kid, pk in recipients.items():
        kem_ct, shared = C.kem_encaps(pk)
        wn, wrapped = C.aes_encrypt(C.derive_kek(shared, f"{document_id}|{kid}".encode()), cek, aad)
        entries[kid] = {"kem_ct": C.b64e(kem_ct), "wrap_nonce": C.b64e(wn), "wrapped_key": C.b64e(wrapped)}
    return {"version": VERSION, "document_id": document_id, "title": title,
            "nonce": C.b64e(nonce), "ciphertext": C.b64e(ct), "recipients": entries}

def for_recipient(pkg: dict, key_id: str) -> dict:
    """Common payload plus only this recipient's encapsulation."""
    if key_id not in pkg["recipients"]: raise PermissionError("recipient not authorized")
    return {**pkg, "recipients": {key_id: pkg["recipients"][key_id]}}

def open_package(pkg: dict, key_id: str, keystore) -> bytes:
    e = pkg["recipients"].get(key_id)
    if e is None: raise PermissionError("recipient not authorized for this package")
    did = pkg["document_id"]; aad = f"TVPKG{pkg['version']}|{did}".encode()
    shared = keystore.decapsulate(C.b64d(e["kem_ct"]))
    cek = C.aes_decrypt(C.derive_kek(shared, f"{did}|{key_id}".encode()), C.b64d(e["wrap_nonce"]), C.b64d(e["wrapped_key"]), aad)
    return C.aes_decrypt(cek, C.b64d(pkg["nonce"]), C.b64d(pkg["ciphertext"]), aad)
