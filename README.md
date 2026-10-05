# TraceVault (SIH26237, Team CYPHER SIX)

Offline multi-recipient post-quantum encrypted PDF distribution with decryption-time fingerprinting, recipient-signed events (ML-DSA-65), a four-node Byzantine-tolerant quorum provenance ledger, fail-closed release, interactive desktop UI, and an evidence/verification pipeline.

```bash
pip install -r requirements.txt
python -m pytest tests                     # 25 tests (Core, E2E, NIST KAT, P0/P1)
python demo.py                             # Full golden path + negative tamper paths
python -m tracevault.server --port 8000    # Starts backend + Web/Desktop UI at http://127.0.0.1:8000
python -m tracevault.verify_ledger <ledger_export.json> <registry.json> # Independent verifier
```

---

## Architecture & Module Mapping

| Module | PRD Area | Description |
|---|---|---|
| `crypto.py`, `keystore.py`, `package.py` | §9 | AES-256-GCM + per-recipient ML-KEM-768, client-local scrypt-encrypted key store |
| `db.py` | §15 | Persistent SQLite database + AES-256-GCM encrypted document vault at rest |
| `client.py` | §7, §14 | Recipient-side zero-trust client: private keys never leave local device |
| `events.py` | §9.3 | Canonical event domain-separation, session-bound watermark digest |
| `watermark.py` | §10, §18 | Spread-spectrum watermark with soft-decision error correction, CLAHE photo preprocessing & rotation invariance (0°, 90°, 180°, 270°) |
| `ledger.py`, `verify_ledger.py` | §13 | 4-node ledger with BFT quorum consensus (3-of-4 ML-DSA attestations), signed checkpoints, standalone CLI verifier |
| `release.py` | §14 | Decrypt → fingerprint → sign → ledger → release with fail-closed gate |
| `evidence.py`, `report_pdf.py` | §11–12 | Multi-check forensic evidence verification pipeline + ReportLab PDF & JSON export |
| `api.py`, `server.py` | §6, §23 | Role-enforced FastAPI with persistent secrets, recipient package delivery, audit log |
| `web/index.html` | §16 | Full Desktop/Web UI: login, admin vault, recipient management, distribution wizard, live 5-step decryption timeline, in-app PDF preview, investigator lab & attack simulator |

---

## Solutions to Prototype Issues (Roadmap §3)

1. **Plaintext Staging on Server (RESOLVED)**:
   - Previously, uploaded PDFs were written to disk unencrypted.
   - Now, documents are immediately encrypted at rest using AES-256-GCM in the SQLite storage vault (`db.py`). Raw plaintext PDF never touches the server filesystem.
2. **Ephemeral API Secrets (RESOLVED)**:
   - Secret key and per-user scrypt salts are now persisted in `api_secret.key` and SQLite, preserving active sessions across restarts.
3. **Packages Held Only in Memory (RESOLVED)**:
   - Distributions and recipient-specific encapsulations are persisted in SQLite, enabling recipients to query and fetch packages on demand via API.
4. **Single-Process Simulated Ledger (RESOLVED)**:
   - Nodes maintain independent directories and post-quantum keys, support BFT-style leader commit with 3-of-4 signed attestations, and can be inspected/verified offline via `tracevault.verify_ledger`.
5. **Read-Only Preservation on Windows (RESOLVED)**:
   - Safe cross-platform file cleanup and permission handling ensures test and demo execution operates seamlessly on Windows.

---

## Delivery Sequence Status (Roadmap §4)

- **Phase A: Foundations (COMPLETE)**:
  - Database, persistent secrets, recipient client flow, NIST KAT tests, encrypted vault at rest.
  - *Exit Criterion Met*: Recipient decrypts via client flow with zero plaintext or private keys on server.
- **Phase B: Ledger (COMPLETE)**:
  - Independent node keyrings, leader consensus rule (3-of-4 quorum), resync, signed checkpoints, standalone verifier CLI.
  - *Exit Criterion Met*: Commit survives 1 node down; single-node history rewrite is detected and rejected.
- **Phase C: UI (COMPLETE)**:
  - All PRD §16 screens built: Auth, Admin Vault, Recipient Registry, Distribution Wizard, Recipient Portal with live 5-stage timeline, In-App PDF Previewer, Investigator Lab, Ledger Monitor, Attack Simulator.
  - *Exit Criterion Met*: Golden path and negative paths runnable directly from the UI.
- **Phase D: Watermark v2 (COMPLETE)**:
  - Soft-decision error correction, CRC-16 integrity, rotation invariance (90°, 180°, 270°), calibrated confidence scoring.
  - *Exit Criterion Met*: Extraction succeeds under rotation, scaling, and JPEG compression (Q50).
- **Phase E: Photo (COMPLETE)**:
  - CLAHE adaptive illumination normalization, contrast normalization, high-pass filtering for camera captures.
- **Phase F: Reporting & Hardening (COMPLETE)**:
  - Official ReportLab PDF report generation, JSON export, NIST Known-Answer Tests (KAT), tamper-evident hash-chained audit trail.

---

## Open Decisions (PRD §29 Recommendations)

1. **Desktop Shell**: FastAPI backend serves the desktop-class web interface at `/` and `/app`. It is packaged to run as a local desktop service or wrapped in Tauri/Electron without modifying the core API.
2. **Crypto Library**: Standardized on PQClean primitives (via `pqcrypto`), validated against NIST parameter lengths and Known-Answer Tests in `tests/test_nist_kat.py`.
3. **Watermark Technique**: Spread-spectrum luminance modulation with pseudo-random noise patterns, enhanced with soft-decision bit decoding and multi-angle orientation sweeps.
4. **Quorum Protocol**: BFT-lite leader commit requiring 3 of 4 signed node attestations (`TV-ATTEST`), tolerating 1 faulty or malicious node.
5. **Canonical Serialization**: Domain-prefixed (`TRACEVAULT-EVENT-v1\n`) canonical JSON (sorted keys, compact separators).
6. **Report Format**: Court-ready PDF generated via ReportLab with cryptographic badges and legal disclaimer, plus machine-readable JSON.

---

## PRD §27 Success Checklist

- [x] **Multi-Recipient Encryption**: 1 AES-256-GCM payload with distinct ML-KEM-768 encapsulations.
- [x] **Key Ownership**: Private keys never leave recipient's local encrypted KeyStore.
- [x] **Session Fingerprinting**: DEC-time session-bound watermark digest embedded into every page.
- [x] **Provenance Ledger**: 4-node ledger with 3-of-4 ML-DSA attestations.
- [x] **Attribution**: Leaked artifacts correctly attributed to recipient and session.
- [x] **Tamper Detection**: Modified ledger blocks or forged signatures fail verification.
- [x] **Fail-Closed Release**: Release blocked if quorum or signature fails.
- [x] **Rotation & Compression Robustness**: Watermark recovered under 90°/180°/270° rotations and JPEG Q50.
- [x] **Report Export**: Automated PDF and JSON report generation.
- [x] **Standalone Verifier**: Independent CLI tool verifies exported ledger integrity without server trust.

## Roles, login and configuration (v3)

| Role | Can do |
|---|---|
| **Submitter** | Drop evidence files to check them, see their own history, download PDF reports |
| **Auditor** | Read-only: all submissions, ledger health (independent verifier), re-check authenticity, activity log |
| **Admin** | Manage users and roles, ledger nodes, the registry; may read everything auditors can |

Sign-in issues a short-lived JWT (HS256). Roles are re-checked against the database on every request, so a
role change or deletion applies immediately.

### First run
```bash
pip install -r requirements.txt
python -m tracevault.keygen > .env        # fresh secrets (see .env.example for every setting)
echo "TV_ADMIN_PASSWORD=choose-a-strong-one" >> .env
python -m tracevault.server               # http://127.0.0.1:8000
```
Upgrading an existing install? Run `python -m tracevault.keygen --migrate ./data > .env`, confirm the app
starts, then securely delete `master.key`, `api_secret.key` and `ledger/node-*/node_key.json`.
Existing `recipient`/`investigator` accounts are renamed to `submitter`/`auditor` automatically.

### Secrets
All secrets come from the environment / `.env` (python-dotenv): `TV_MASTER_KEY`, `TV_JWT_SECRET`,
`TV_NODE_1..4_KEY`. Nothing secret is read from or written to `data/`. Per-user keystores stay passphrase
encrypted (file in `TV_KEYSTORE_DIR`, or `TV_KEYSTORE_<USER>` env var); passphrases are never stored.

### Ledger concurrency
Every append to a node's `chain.jsonl` and every commit is guarded by `filelock` (cross-process and
cross-thread). Under the lock the node re-reads the file tail and re-checks the chain link, then writes and
fsyncs, so concurrent submissions cannot fork or interleave the chain.

### Where each original feature lives in the web UI (v3.1)

| Original screen | Now | Who |
|---|---|---|
| System overview | Overview | Admin |
| Admin & documents (encrypted intake) | Documents | Admin |
| Recipient registry (register, revoke) | Recipients (+ self-service key setup under My documents) | Admin / Submitter |
| Distribution wizard | Share | Admin |
| Recipient decrypt & release (5-step timeline, viewer, download) | My documents | Submitter |
| Investigator and leak lab (report, PDF/JSON export) | Check a file / Evidence | Submitter, Admin (Auditor: Submissions) |
| 4-node quorum ledger (toggle nodes, blocks, verifier export) | Ledger | Admin (Auditor: read-only) |
| Golden path + attack simulator | Tests and demo / Security tests | Admin (Auditor: attacks only) |
| Tamper-evident audit trail | Activity | Admin, Auditor |

Admins and auditors can switch on **Technical details** (top bar) to see hashes, key IDs and block links.
The attack tests now run for real against throw-away copies of the ledger and registry; live data is never touched.

## Supported file types (v3.3)
Upload documents or check evidence in: **PDF, Word (.doc/.docx), PowerPoint (.ppt/.pptx), Excel (.xls/.xlsx), OpenDocument (.odt/.odp/.ods), RTF, TXT, CSV, PNG, JPEG, GIF, BMP, WebP, TIFF**.
- Types are detected from file *content*, not the extension. Unsupported files get 415, damaged ones 422.
- PDFs and PNG/JPEG are stored as-is; GIF/BMP/WebP/TIFF become PNG; Office/OpenDocument/RTF/TXT/CSV are converted to PDF at intake so every released copy carries its tracking mark (released as PDF, images as PNG).
- Office conversion needs **LibreOffice** on the server (`apt install libreoffice`); without it those uploads return 501 with a clear message and PDF/images still work.
- Evidence checking also accepts Office files: embedded pictures (e.g. a screenshot pasted into a deck) are searched first, then the file is rendered to PDF.
- `GET /formats` reports what the server supports.
