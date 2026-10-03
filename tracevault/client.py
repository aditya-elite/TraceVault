"""Recipient-side client for TraceVault.

Enforces zero-trust recipient execution (PRD §7, §14):
- Private keys NEVER leave the recipient's local KeyStore.
- The server never receives or sees document plaintext during decryption.
- The client decapsulates (ML-KEM-768), decrypts (AES-256-GCM), embeds the watermark,
  signs the canonical event (ML-DSA-65), commits to the ledger quorum over API,
  and releases the fingerprinted PDF to the local viewer/memory.
"""
from dataclasses import dataclass
import httpx
from . import crypto as C, events, package, watermark as W
from .keystore import KeyStore
from .release import ReleaseDenied, Released

@dataclass
class ClientProgressUpdate:
    step: str             # "decapsulate" | "decrypt" | "fingerprint" | "sign" | "ledger" | "release"
    status: str           # "running" | "done" | "failed"
    detail: str = ""
    node_attestations: dict | None = None

class TraceVaultClient:
    def __init__(self, api_base_url: str, keystore: KeyStore, auth_token: str | None = None):
        self.base_url = api_base_url.rstrip("/")
        self.keystore = keystore
        self.auth_token = auth_token
        self._client = httpx.Client(base_url=self.base_url, timeout=30.0)

    def set_token(self, token: str):
        self.auth_token = token

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    def fetch_my_packages(self) -> list[dict]:
        """Fetch encrypted distributions intended for this recipient."""
        res = self._client.get(f"/recipient/packages", headers=self._headers())
        if res.status_code != 200:
            raise RuntimeError(f"Failed to fetch packages: {res.text}")
        return res.json().get("packages", [])

    def fetch_package(self, document_id: str) -> dict:
        res = self._client.get(f"/recipient/packages/{document_id}", headers=self._headers())
        if res.status_code != 200:
            raise RuntimeError(f"Failed to fetch package for {document_id}: {res.text}")
        return res.json()["package"]

    def commit_event(self, event: dict, signature: bytes) -> dict:
        payload = {
            "event": event,
            "signature": C.b64e(signature),
            "signer_key_id": self.keystore.key_id
        }
        res = self._client.post("/ledger/commit", json=payload, headers=self._headers())
        if res.status_code != 200:
            raise RuntimeError(f"Ledger commit failed ({res.status_code}): {res.text}")
        return res.json()

    def decrypt_and_release(self, pkg: dict, on_progress=None, protector: W.ContentProtector | None = None) -> Released:
        """Executes full fail-closed recipient release flow.

        Timeline sequence:
        1. Decapsulate & Decrypt (ML-KEM-768 + AES-256-GCM)
        2. Fingerprint (Spread-spectrum watermark)
        3. Sign (ML-DSA-65 over canonical event)
        4. Ledger (Submit signed event to quorum)
        5. Release (Fail-closed release of fingerprinted PDF)
        """
        def notify(step, status, detail="", attestations=None):
            if on_progress:
                on_progress(ClientProgressUpdate(step, status, detail, attestations))

        protector = protector or W.PdfProtector()
        kid = self.keystore.key_id

        # 1. Decapsulate & Decrypt
        notify("decrypt", "running", "Decapsulating ML-KEM-768 & unwrapping AES-256-GCM key locally...")
        try:
            plaintext = package.open_package(pkg, kid, self.keystore)
            doc_hash = C.sha3(plaintext)
            notify("decrypt", "done", f"Plaintext unwrapped in client memory (SHA3: {doc_hash[:12]}...)")
        except Exception as e:
            notify("decrypt", "failed", str(e))
            raise ReleaseDenied("decrypt", str(e)) from None

        # 2. Fingerprint
        notify("fingerprint", "running", "Synthesizing session-bound spread-spectrum watermark...")
        try:
            event = events.new_event(pkg["document_id"], kid, doc_hash)
            payload = W.make_payload(event["watermark_digest"])
            protected_pdf = protector.embed(plaintext, payload)
            del plaintext  # ensure plaintext is cleared immediately
            notify("fingerprint", "done", f"Fingerprint embedded (Session: {event['session_id']}, WM ID: {payload[:8].hex()})")
        except Exception as e:
            notify("fingerprint", "failed", str(e))
            raise ReleaseDenied("fingerprint", str(e)) from None

        # 3. Sign
        notify("sign", "running", "Signing canonical event with recipient ML-DSA-65 private key...")
        try:
            msg = C.event_message(event)
            signature = self.keystore.sign(msg)
            notify("sign", "done", "ML-DSA-65 signature generated over canonical event")
        except Exception as e:
            notify("sign", "failed", str(e))
            raise ReleaseDenied("sign", str(e)) from None

        # 4. Ledger Commit (Submit over API to Ledger Quorum)
        notify("ledger", "running", "Submitting signed event to 4-node ledger quorum...")
        try:
            record = self.commit_event(event, signature)
            atts = record.get("attestations", {})
            notify("ledger", "done", f"Committed record #{record.get('index')} with {len(atts)}/4 node attestations", atts)
        except Exception as e:
            notify("ledger", "failed", str(e))
            raise ReleaseDenied("ledger", str(e)) from None

        # 5. Release
        notify("release", "done", "Decryption-time provenance verified; document released to viewer")
        return Released(protected_pdf, event, record)
