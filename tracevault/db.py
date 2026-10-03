"""Persistent SQLite database and encrypted storage for TraceVault.

Provides persistent storage for users, recipients, encrypted documents, packages,
ledger records, evidence cases, and a tamper-evident hash-chained audit log.
Fixes prototype issues:
- Documents are immediately encrypted at rest with AES-256-GCM (no plaintext on disk).
- Master secrets and user salt/hash persist across restarts.
- Packages are stored persistently so recipients can retrieve them on demand.
"""
import hashlib, hmac, json, os, sqlite3, time
from . import crypto as C

class Database:
    def __init__(self, db_path: str, master_key: bytes | None = None):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.master_key = master_key or self._get_or_create_master_key(os.path.dirname(db_path))
        self._init_schema()

    @staticmethod
    def _get_or_create_master_key(dir_path: str) -> bytes:
        key_file = os.path.join(dir_path, "master.key")
        if os.path.exists(key_file):
            return open(key_file, "rb").read()
        key = os.urandom(32)
        with open(key_file, "wb") as f:
            f.write(key)
        try:
            os.chmod(key_file, 0o600)
        except Exception:
            pass
        return key

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self.get_connection() as conn:
            c = conn.cursor()
            c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recipients (
                recipient_key_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                kem_pk TEXT NOT NULL,
                dsa_pk TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                registered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS documents (
                document_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                nonce_b64 TEXT NOT NULL,
                encrypted_content_b64 TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS distributions (
                distribution_id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (document_id) REFERENCES documents(document_id)
            );

            CREATE TABLE IF NOT EXISTS packages (
                package_id TEXT PRIMARY KEY,
                distribution_id TEXT NOT NULL,
                document_id TEXT NOT NULL,
                recipient_key_id TEXT NOT NULL,
                package_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (distribution_id) REFERENCES distributions(distribution_id),
                FOREIGN KEY (document_id) REFERENCES documents(document_id)
            );

            CREATE TABLE IF NOT EXISTS evidence_cases (
                case_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                evidence_sha3 TEXT NOT NULL,
                investigator TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL,
                prev_entry_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            """)
            conn.commit()

    # --- User Management ---
    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()

    def add_user(self, username: str, password: str, role: str):
        salt = os.urandom(16)
        pw_hash = self.hash_password(password, salt)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT OR REPLACE INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, pw_hash, C.b64e(salt), role, now)
            )
            conn.commit()

    def verify_user(self, username: str, password: str) -> dict | None:
        with self.get_connection() as conn:
            row = conn.cursor().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return None
            salt = C.b64d(row["salt"])
            computed = self.hash_password(password, salt)
            if hmac.compare_digest(row["password_hash"], computed):
                return {"username": row["username"], "role": row["role"]}
        return None

    def list_users(self) -> list[dict]:
        with self.get_connection() as conn:
            rows = conn.cursor().execute("SELECT username, role, created_at FROM users").fetchall()
            return [dict(r) for r in rows]

    # --- Encrypted Document Vault (Encrypted at rest) ---
    def store_document(self, document_id: str, title: str, plaintext_pdf: bytes, owner: str) -> str:
        sha3 = C.sha3(plaintext_pdf)
        aad = f"DOC_VAULT|{document_id}".encode()
        nonce, ciphertext = C.aes_encrypt(self.master_key, plaintext_pdf, aad)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT OR REPLACE INTO documents (document_id, title, original_hash, owner, status, nonce_b64, encrypted_content_b64, created_at) "
                "VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
                (document_id, title, sha3, owner, C.b64e(nonce), C.b64e(ciphertext), now)
            )
            conn.commit()
        return sha3

    def get_document_meta(self, document_id: str) -> dict | None:
        with self.get_connection() as conn:
            row = conn.cursor().execute("SELECT document_id, title, original_hash, owner, status, created_at FROM documents WHERE document_id = ?",
                                        (document_id,)).fetchone()
            return dict(row) if row else None

    def get_document_content(self, document_id: str) -> bytes | None:
        with self.get_connection() as conn:
            row = conn.cursor().execute("SELECT nonce_b64, encrypted_content_b64 FROM documents WHERE document_id = ?",
                                        (document_id,)).fetchone()
            if not row:
                return None
            aad = f"DOC_VAULT|{document_id}".encode()
            return C.aes_decrypt(self.master_key, C.b64d(row["nonce_b64"]), C.b64d(row["encrypted_content_b64"]), aad)

    def list_documents(self) -> list[dict]:
        with self.get_connection() as conn:
            rows = conn.cursor().execute("SELECT document_id, title, original_hash, owner, status, created_at FROM documents ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def revoke_document(self, document_id: str):
        with self.get_connection() as conn:
            conn.cursor().execute("UPDATE documents SET status = 'revoked' WHERE document_id = ?", (document_id,))
            conn.commit()

    # --- Recipient Registry Persistence ---
    def add_recipient(self, recipient_key_id: str, user_id: str, display_name: str, kem_pk: str, dsa_pk: str):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT OR REPLACE INTO recipients (recipient_key_id, user_id, display_name, kem_pk, dsa_pk, status, registered_at) "
                "VALUES (?, ?, ?, ?, ?, 'active', ?)",
                (recipient_key_id, user_id, display_name, kem_pk, dsa_pk, now)
            )
            conn.commit()

    def get_recipient(self, recipient_key_id: str) -> dict | None:
        with self.get_connection() as conn:
            row = conn.cursor().execute("SELECT * FROM recipients WHERE recipient_key_id = ?", (recipient_key_id,)).fetchone()
            return dict(row) if row else None

    def get_recipient_by_user(self, user_id: str) -> dict | None:
        with self.get_connection() as conn:
            row = conn.cursor().execute("SELECT * FROM recipients WHERE user_id = ? AND status = 'active'", (user_id,)).fetchone()
            return dict(row) if row else None

    def list_recipients(self) -> list[dict]:
        with self.get_connection() as conn:
            rows = conn.cursor().execute("SELECT * FROM recipients ORDER BY registered_at ASC").fetchall()
            return [dict(r) for r in rows]

    def revoke_recipient(self, recipient_key_id: str):
        with self.get_connection() as conn:
            conn.cursor().execute("UPDATE recipients SET status = 'revoked' WHERE recipient_key_id = ?", (recipient_key_id,))
            conn.commit()

    # --- Packages & Distributions ---
    def store_distribution(self, distribution_id: str, document_id: str, created_by: str,
                           recipient_packages: dict[str, dict]):
        """recipient_packages: {recipient_key_id: package_dict_for_recipient}"""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.get_connection() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT OR REPLACE INTO distributions (distribution_id, document_id, created_by, created_at) VALUES (?, ?, ?, ?)",
                (distribution_id, document_id, created_by, now)
            )
            for kid, pkg in recipient_packages.items():
                pkg_id = f"{distribution_id}_{kid}"
                c.execute(
                    "INSERT OR REPLACE INTO packages (package_id, distribution_id, document_id, recipient_key_id, package_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (pkg_id, distribution_id, document_id, kid, json.dumps(pkg), now)
                )
            conn.commit()

    def get_packages_for_recipient(self, recipient_key_id: str) -> list[dict]:
        with self.get_connection() as conn:
            rows = conn.cursor().execute(
                "SELECT p.package_id, p.distribution_id, p.document_id, p.recipient_key_id, p.package_json, p.created_at, "
                "d.title, d.original_hash, d.status as document_status "
                "FROM packages p JOIN documents d ON p.document_id = d.document_id "
                "WHERE p.recipient_key_id = ? ORDER BY p.created_at DESC",
                (recipient_key_id,)
            ).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["package"] = json.loads(r["package_json"])
                res.append(item)
            return res

    def get_package_by_doc_and_recipient(self, document_id: str, recipient_key_id: str) -> dict | None:
        with self.get_connection() as conn:
            row = conn.cursor().execute(
                "SELECT package_json FROM packages WHERE document_id = ? AND recipient_key_id = ? ORDER BY created_at DESC LIMIT 1",
                (document_id, recipient_key_id)
            ).fetchone()
            return json.loads(row["package_json"]) if row else None

    # --- Evidence Cases ---
    def store_evidence_case(self, case_id: str, filename: str, evidence_sha3: str, investigator: str,
                            status: str, report: dict):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT OR REPLACE INTO evidence_cases (case_id, filename, evidence_sha3, investigator, status, report_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (case_id, filename, evidence_sha3, investigator, status, json.dumps(report), now)
            )
            conn.commit()

    def list_evidence_cases(self) -> list[dict]:
        with self.get_connection() as conn:
            rows = conn.cursor().execute("SELECT case_id, filename, evidence_sha3, investigator, status, created_at FROM evidence_cases ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def get_evidence_case(self, case_id: str) -> dict | None:
        with self.get_connection() as conn:
            row = conn.cursor().execute("SELECT * FROM evidence_cases WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            res["report"] = json.loads(res["report_json"])
            return res

    # --- Tamper-Evident Hash-Chained Audit Log ---
    def append_audit(self, actor: str, action: str, **kw) -> str:
        now = time.time()
        details_json = json.dumps(kw, sort_keys=True)
        with self.get_connection() as conn:
            c = conn.cursor()
            last = c.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = last["entry_hash"] if last else "0" * 64
            entry_hash = C.sha3(str(now).encode(), actor.encode(), action.encode(), details_json.encode(), prev_hash.encode())
            c.execute(
                "INSERT INTO audit_log (timestamp, actor, action, details_json, prev_entry_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (now, actor, action, details_json, prev_hash, entry_hash)
            )
            conn.commit()
            return entry_hash

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        with self.get_connection() as conn:
            rows = conn.cursor().execute(
                "SELECT id, timestamp, actor, action, details_json, prev_entry_hash, entry_hash FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item["details_json"])
                res.append(item)
            return res

    def verify_audit_log(self) -> bool:
        with self.get_connection() as conn:
            rows = conn.cursor().execute("SELECT timestamp, actor, action, details_json, prev_entry_hash, entry_hash FROM audit_log ORDER BY id ASC").fetchall()
            prev = "0" * 64
            for r in rows:
                if r["prev_entry_hash"] != prev:
                    return False
                expected = C.sha3(str(r["timestamp"]).encode(), r["actor"].encode(), r["action"].encode(), r["details_json"].encode(), prev.encode())
                if r["entry_hash"] != expected:
                    return False
                prev = r["entry_hash"]
            return True
