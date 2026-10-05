"""Primitives: AES-256-GCM, ML-KEM-768, ML-DSA-65, SHA3-256, canonical serialization."""
import base64, hashlib, json, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768 as _kem
from pqcrypto.sign import ml_dsa_65 as _dsa
from .config import ConfigError, env

EVENT_DOMAIN = b"TRACEVAULT-EVENT-v1\n"

def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s)

def sha3(*parts: bytes) -> str:
    """SHA3-256 over length-prefixed parts (unambiguous concatenation)."""
    h = hashlib.sha3_256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big")); h.update(p)
    return h.hexdigest()

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def event_message(event: dict) -> bytes:
    return EVENT_DOMAIN + canonical(event)

def key_id(kem_pk: bytes, dsa_pk: bytes) -> str:
    return "K-" + sha3(kem_pk, dsa_pk)[:12]

def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b""):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)

def aes_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)

def derive_kek(shared: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, None, b"tracevault-kek-v1|" + info).derive(shared)

def kem_keygen(): return _kem.keygen()
def kem_encaps(pk: bytes): return _kem.encaps(pk)
def kem_decaps(sk: bytes, ct: bytes): return _kem.decaps(sk, ct)

def dsa_keygen(): return _dsa.keygen()
def dsa_sign(sk: bytes, msg: bytes) -> bytes: return _dsa.sign(sk, msg)
def dsa_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return _dsa.verify(pk, msg, sig) is not False
    except Exception:
        return False

# --- Secrets loaded from the environment (never from flat files) ---
def key_from_env(name: str, length: int = 32) -> bytes:
    """Read a base64-encoded symmetric key of exactly `length` bytes from env var `name`."""
    try:
        raw = b64d(env(name))
    except ConfigError:
        raise
    except Exception:
        raise ConfigError(f"{name} is not valid base64")
    if len(raw) != length:
        raise ConfigError(f"{name} must decode to {length} bytes (got {len(raw)})")
    return raw

def keypair_from_env(name: str) -> tuple[bytes, bytes]:
    """Read an ML-DSA keypair stored as '<b64 public>:<b64 secret>' in env var `name`."""
    try:
        pk, sk = env(name).split(":")
        return b64d(pk), b64d(sk)
    except ConfigError:
        raise
    except Exception:
        raise ConfigError(f"{name} must be '<base64 public key>:<base64 secret key>'")

def keypair_to_env(pk: bytes, sk: bytes) -> str:
    return b64e(pk) + ":" + b64e(sk)
