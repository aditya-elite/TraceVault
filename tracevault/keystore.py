"""Recipient-local encrypted key store. Private keys never leave this object/device."""
import json, os
from .config import load_env
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from . import crypto as C

class KeyStore:
    """Passphrase-encrypted key container. The passphrase is never stored; the encrypted blob can live in a
    file (path) or in an environment variable (see `from_env`)."""
    def __init__(self, path=None, blob: dict | None = None):
        self.path, self._blob, self._sk = path, blob, None

    @staticmethod
    def env_name(user: str) -> str:
        return "TV_KEYSTORE_" + "".join(c if c.isalnum() else "_" for c in user).upper()

    @classmethod
    def from_env(cls, user: str):
        """Load `user`'s encrypted keystore from env var TV_KEYSTORE_<USER> (base64 of the keystore JSON)."""
        load_env()
        raw = os.environ.get(cls.env_name(user))
        return cls(blob=json.loads(C.b64d(raw))) if raw else None

    @classmethod
    def locate(cls, user: str, keystore_dir: str | None = None):
        """Env var first; otherwise `<TV_KEYSTORE_DIR>/<user>.keys`. Returns None if neither exists."""
        ks = cls.from_env(user)
        if ks:
            return ks
        d = keystore_dir or os.environ.get("TV_KEYSTORE_DIR")
        p = os.path.join(d, f"{user}.keys") if d else None
        return cls(p) if p and os.path.exists(p) else None

    def _load(self) -> dict:
        if self._blob is not None:
            return self._blob
        with open(self.path) as f:
            return json.load(f)

    def export_blob(self) -> str:
        """Base64 of the encrypted keystore, suitable for TV_KEYSTORE_<USER>."""
        return C.b64e(json.dumps(self._load()).encode())

    @staticmethod
    def _kdf(pw: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pw.encode())

    @classmethod
    def create(cls, path, passphrase: str):
        kem_pk, kem_sk = C.kem_keygen(); dsa_pk, dsa_sk = C.dsa_keygen()
        salt = os.urandom(16)
        nonce, ct = C.aes_encrypt(cls._kdf(passphrase, salt),
                                  json.dumps({"kem_sk": C.b64e(kem_sk), "dsa_sk": C.b64e(dsa_sk)}).encode(), b"tv-keystore-v1")
        pub = {"kem_pk": C.b64e(kem_pk), "dsa_pk": C.b64e(dsa_pk), "key_id": C.key_id(kem_pk, dsa_pk)}
        with open(path, "w") as f:
            json.dump({"salt": C.b64e(salt), "nonce": C.b64e(nonce), "ct": C.b64e(ct), "public": pub}, f)
        os.chmod(path, 0o600)
        return cls(path)

    @property
    def public(self) -> dict:
        return self._load()["public"]

    @property
    def key_id(self) -> str: return self.public["key_id"]

    def unlock(self, passphrase: str):
        d = self._load()
        try:
            raw = C.aes_decrypt(self._kdf(passphrase, C.b64d(d["salt"])), C.b64d(d["nonce"]), C.b64d(d["ct"]), b"tv-keystore-v1")
        except Exception:
            raise PermissionError("key store unlock failed")
        self._sk = {k: C.b64d(v) for k, v in json.loads(raw).items()}
        return self

    def lock(self): self._sk = None

    def _need(self):
        if self._sk is None: raise PermissionError("key store locked")

    def decapsulate(self, ct: bytes) -> bytes:
        self._need(); return C.kem_decaps(self._sk["kem_sk"], ct)

    def sign(self, msg: bytes) -> bytes:
        self._need(); return C.dsa_sign(self._sk["dsa_sk"], msg)
