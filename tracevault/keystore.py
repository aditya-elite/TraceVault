"""Recipient-local encrypted key store. Private keys never leave this object/device."""
import json, os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from . import crypto as C

class KeyStore:
    def __init__(self, path):
        self.path, self._sk = path, None

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
        return json.load(open(self.path))["public"]

    @property
    def key_id(self) -> str: return self.public["key_id"]

    def unlock(self, passphrase: str):
        d = json.load(open(self.path))
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
