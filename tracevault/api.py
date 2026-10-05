"""FastAPI orchestration: JWT authentication, role-based access control (RBAC), encrypted storage.

Roles
  submitter  upload evidence, see their own history, download PDF reports
  auditor    read-only: browse all submissions, query/verify the ledger, re-check authenticity
  admin      manage users, nodes and the registry (and may read everything auditors can)

The browser UI talks to this module only through the REST endpoints below; it never touches db.py or
ledger.py. The API strictly rejects any private-key fields in schemas (PRD §6, §23).
"""
import copy, io, os, re, secrets, shutil, tempfile, threading, time, uuid
import jwt
from fastapi import Depends, FastAPI, HTTPException, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from . import formats as F
from . import crypto as C, package, evidence, events
from .config import ConfigError, env, env_bool, env_int, load_env
from .db import Database
from .keystore import KeyStore
from .ledger import Ledger
from .registry import Registry
from .release import ReleaseDenied, decrypt_and_release
from .report_pdf import generate_report_pdf
from .verify_ledger import verify_export
from .ledger import Ledger as _Ledger

ROLES = ("submitter", "auditor", "admin")
JWT_ALG, JWT_ISS = "HS256", "tracevault"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MAX_FAILS, LOCKOUT_SECONDS = 5, 60

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

class Login(Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)

class UserIn(Strict):
    username: str
    password: str = Field(min_length=8, max_length=128)
    role: str

class PasswordReset(Strict):
    password: str = Field(min_length=8, max_length=128)

class PasswordChange(Strict):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=8, max_length=128)

class RoleIn(Strict):
    role: str

class DocIn(Strict):
    title: str
    content_b64: str
    filename: str = ""        # optional hint; content is always sniffed

class RecipIn(Strict):
    user_id: str
    display_name: str
    kem_pk: str
    dsa_pk: str

class DistIn(Strict):
    document_id: str
    recipient_key_ids: list[str]

class CommitIn(Strict):
    event: dict
    signature: str
    signer_key_id: str

class EvidenceIn(Strict):
    filename: str = Field(min_length=1, max_length=200)
    content_b64: str

class EnrollIn(Strict):
    display_name: str = Field(min_length=2, max_length=80)
    passphrase: str = Field(min_length=8, max_length=128)

class AdminEnrollIn(EnrollIn):
    user_id: str

class RecipientDecryptIn(Strict):
    document_id: str
    keystore_passphrase: str

def _jwt_secret(explicit: bytes | str | None) -> str | bytes:
    s = explicit if explicit else env("TV_JWT_SECRET")
    if len(s) < 32:
        raise ConfigError("TV_JWT_SECRET must be at least 32 characters")
    return s

def create_app(data_dir: str, users: dict | None = None, secret: bytes | str | None = None) -> FastAPI:
    """Creates the TraceVault FastAPI application. Secrets come from the environment (see .env.example)."""
    load_env()
    os.makedirs(data_dir, exist_ok=True)
    jwt_secret = _jwt_secret(secret)
    ttl = env_int("TV_JWT_TTL_MINUTES", 60) * 60
    max_bytes = env_int("TV_MAX_UPLOAD_MB", 25) * 1024 * 1024
    keystore_dir = os.environ.get("TV_KEYSTORE_DIR") or os.path.join(data_dir, "keystores")
    evidence_dir = os.path.join(data_dir, "evidence")

    db = Database(os.path.join(data_dir, "tracevault.db"))
    reg = Registry(os.path.join(data_dir, "registry.json"))
    ledger = Ledger(os.path.join(data_dir, "ledger"))

    # Seed users: explicit ones (tests/automation), then the first-run admin from the environment.
    for u, v in (users or {}).items():
        db.ensure_user(u, v["password"], v["role"])
    if os.environ.get("TV_ADMIN_PASSWORD"):
        db.ensure_user(os.environ.get("TV_ADMIN_USER", "admin"), os.environ["TV_ADMIN_PASSWORD"], "admin")

    app = FastAPI(title="TraceVault", version="3.0.0", docs_url=None, redoc_url=None)
    app.state.db, app.state.registry, app.state.ledger, app.state.data_dir = db, reg, ledger, data_dir

    origins = [o.strip() for o in os.environ.get("TV_CORS_ORIGINS", "").split(",") if o.strip()]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; frame-ancestors 'none'")
        return resp

    def log(actor, action, **kw):
        db.append_audit(actor, action, **kw)

    # ---------------------------------------------------------------- JWT + RBAC
    def mint(user: str, role: str) -> str:
        now = int(time.time())
        return jwt.encode({"sub": user, "role": role, "iat": now, "exp": now + ttl, "iss": JWT_ISS,
                           "jti": uuid.uuid4().hex}, jwt_secret, algorithm=JWT_ALG)

    def auth(*roles):
        """Dependency: valid JWT AND the user still exists with a permitted role (checked against the DB, so
        deleting a user or changing their role takes effect immediately, not at token expiry)."""
        def dep(authorization: str = Header(default="")):
            token = authorization[7:] if authorization[:7].lower() == "bearer " else ""
            try:
                t = jwt.decode(token, jwt_secret, algorithms=[JWT_ALG], issuer=JWT_ISS,
                               options={"require": ["exp", "iat", "sub", "iss"]})
            except jwt.PyJWTError:
                raise HTTPException(401, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
            u = db.get_user(t["sub"])
            if not u:
                raise HTTPException(401, "account no longer exists", headers={"WWW-Authenticate": "Bearer"})
            if u["role"] not in roles:
                raise HTTPException(403, f"role '{u['role']}' not permitted")
            return {"username": u["username"], "role": u["role"]}
        return dep

    any_user = auth(*ROLES)

    _fails: dict[str, list] = {}   # username -> [count, locked_until]
    _fails_lock = threading.Lock()

    @app.post("/auth/login")
    def login(b: Login):
        key = b.username.lower()
        with _fails_lock:
            f = _fails.get(key)
            if f and f[1] > time.time():
                raise HTTPException(429, f"too many attempts, try again in {int(f[1] - time.time()) + 1}s")
        u = db.verify_user(b.username, b.password)
        if not u:
            with _fails_lock:
                f = _fails.setdefault(key, [0, 0.0])
                f[0] += 1
                if f[0] >= MAX_FAILS:
                    f[0], f[1] = 0, time.time() + LOCKOUT_SECONDS
            log(b.username[:64], "login.failed")
            raise HTTPException(401, "wrong username or password")
        with _fails_lock:
            _fails.pop(key, None)
        log(u["username"], "login", role=u["role"])
        return {"token": mint(u["username"], u["role"]), "token_type": "bearer", "expires_in": ttl,
                "username": u["username"], "role": u["role"]}

    @app.get("/auth/me")
    def me(caller=Depends(any_user)):
        return caller

    @app.post("/auth/password")
    def change_password(b: PasswordChange, caller=Depends(any_user)):
        if not db.verify_user(caller["username"], b.current_password):
            raise HTTPException(401, "current password is wrong")
        db.set_password(caller["username"], b.new_password)
        log(caller["username"], "password.change")
        return {"status": "ok"}

    # ---------------------------------------------------------------- helpers
    def summary(row: dict) -> dict:
        return {"case_id": row["case_id"], "date": row["created_at"], "submitter": row["investigator"],
                "filename": row["filename"], "status": row["status"], **evidence.verdict(row["status"])}

    def load_case(case_id: str, caller: dict) -> dict:
        c = db.get_evidence_case(case_id)
        # Submitters only ever see their own cases; "not found" (not 403) so IDs cannot be probed.
        if not c or (caller["role"] == "submitter" and c["investigator"] != caller["username"]):
            raise HTTPException(404, "case not found")
        return c

    def pdf_response(c: dict) -> Response:
        return Response(content=generate_report_pdf(c["report"]), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="TraceVault_Report_{c["case_id"]}.pdf"'})

    def json_response(c: dict) -> JSONResponse:
        return JSONResponse(content=c["report"], headers={
            "Content-Disposition": f'attachment; filename="TraceVault_Report_{c["case_id"]}.json"'})

    def ledger_summary() -> dict:
        v = verify_export(ledger.export_chain(), reg.d)
        valid = sum(1 for n in v["nodes"].values() if n["valid"])
        return {"verified": v["verified"], "blocks": v["quorum_records"], "nodes_valid": valid,
                "nodes_total": len(v["nodes"]), "errors": v["errors"],
                "nodes": {k: {"valid": n["valid"], "records": n["record_count"], "errors": n["errors"],
                                "online": next((x.online for x in ledger.nodes if x.id == k), True)}
                          for k, n in v["nodes"].items()}}

    # ================================================================ SUBMITTER
    @app.post("/submitter/evidence")
    def submit_evidence(b: EvidenceIn, caller=Depends(auth("submitter", "admin"))):
        who = caller["username"]
        if len(b.content_b64) > max_bytes * 4 // 3 + 8:
            raise HTTPException(413, f"file too large (limit {max_bytes // 1048576} MB)")
        try:
            raw = C.b64d(b.content_b64)
        except Exception:
            raise HTTPException(400, "file content is not valid base64")
        if not raw:
            raise HTTPException(400, "empty file")
        rep = evidence.process_case(raw, os.path.basename(b.filename.replace("\\", "/")), reg, ledger, evidence_dir, who)
        rep["case_id"] += "-" + uuid.uuid4().hex[:4]    # one record per submission, even for identical files
        db.store_evidence_case(rep["case_id"], rep["evidence_file"], rep["evidence_sha3_256"], who, rep["status"], rep)
        log(who, "evidence.submit", case_id=rep["case_id"], status=rep["status"])
        return {"case_id": rep["case_id"], "filename": rep["evidence_file"], "status": rep["status"],
                "date": rep["submitted_at"], "submitter": who, **evidence.verdict(rep["status"])}

    @app.get("/submitter/evidence")
    def my_evidence(caller=Depends(auth("submitter", "admin"))):
        return {"items": [summary(r) for r in db.list_evidence_cases(submitter=caller["username"])]}

    @app.get("/submitter/evidence/{case_id}")
    def my_evidence_detail(case_id: str, caller=Depends(auth("submitter", "admin"))):
        c = load_case(case_id, caller)
        return {**summary(c), "report": c["report"]}

    @app.get("/submitter/evidence/{case_id}/pdf")
    def my_evidence_pdf(case_id: str, caller=Depends(auth("submitter", "admin"))):
        return pdf_response(load_case(case_id, caller))

    @app.get("/submitter/evidence/{case_id}/json")
    def my_evidence_json(case_id: str, caller=Depends(auth("submitter", "admin"))):
        return json_response(load_case(case_id, caller))

    # ================================================================ AUDITOR (read-only; admin may read too)
    read_roles = auth("auditor", "admin")

    @app.get("/auditor/evidence")
    def all_evidence(caller=Depends(read_roles)):
        return {"items": [summary(r) for r in db.list_evidence_cases()]}

    @app.get("/auditor/evidence/{case_id}")
    def evidence_detail(case_id: str, caller=Depends(read_roles)):
        c = load_case(case_id, caller)
        return {**summary(c), "report": c["report"]}

    @app.get("/auditor/evidence/{case_id}/pdf")
    def evidence_pdf(case_id: str, caller=Depends(read_roles)):
        return pdf_response(load_case(case_id, caller))

    @app.get("/auditor/evidence/{case_id}/json")
    def evidence_json(case_id: str, caller=Depends(read_roles)):
        return json_response(load_case(case_id, caller))

    @app.get("/auditor/ledger/blocks")
    def ledger_blocks(caller=Depends(read_roles)):
        """Quorum blocks, newest first, with human-readable recipient names."""
        health = ledger.verify(reg)["nodes"]
        good = [n for n in ledger.nodes if health[n.id]["ok"]] or ledger.nodes
        src = max(good, key=lambda n: len(n.records))
        out = []
        for r in reversed(src.records):
            kid = r["signer_key_id"]
            out.append({"index": r["index"], "record_hash": r["record_hash"], "prev_hash": r["prev_hash"],
                        "session_id": r["event"].get("session_id"), "document_id": r["event"].get("document_id"),
                        "recipient_key_id": kid, "recipient": (reg.recipient(kid) or {}).get("display_name", "Unknown"),
                        "timestamp": r["event"].get("timestamp"), "attestations": len(r.get("attestations", {}))})
        return {"blocks": out}

    @app.get("/auditor/evidence/{case_id}/authenticity")
    def authenticity(case_id: str, caller=Depends(read_roles)):
        """Re-run the verification on the preserved original file (nothing is written) and confirm the stored
        file still matches the hash recorded at submission time."""
        c = load_case(case_id, caller)
        path = os.path.join(evidence_dir, f"{c['evidence_sha3'][:16]}_{os.path.basename(c['filename'])}")
        if not os.path.exists(path):
            return {"case_id": case_id, "file_intact": False, "reason": "original file is missing", "verdict": "failed",
                    "headline": "Failed", "explain": "The stored original file could not be found."}
        with open(path, "rb") as f:
            data = f.read()
        intact = C.sha3(data) == c["evidence_sha3"]
        rep = evidence.process_case(data, c["filename"], reg, ledger, evidence_dir, caller["username"])
        v = evidence.verdict(rep["status"] if intact else evidence.LOW)
        log(caller["username"], "evidence.recheck", case_id=case_id, intact=intact, status=rep["status"])
        return {"case_id": case_id, "file_intact": intact, "status": rep["status"], "recorded_status": c["status"],
                "unchanged_since_submission": rep["status"] == c["status"], **v,
                "checks": [{"name": k["name"], "passed": k["passed"]} for k in rep["checks"]]}

    @app.get("/auditor/ledger")
    def ledger_view(caller=Depends(read_roles)):
        return ledger_summary()

    @app.get("/auditor/ledger/export")
    def ledger_export(caller=Depends(read_roles)):
        return {"ledger": ledger.export_chain(), "registry": reg.d}

    @app.get("/auditor/audit-log")
    def audit_log(caller=Depends(read_roles)):
        return {"verified": db.verify_audit_log(), "entries": db.get_audit_log(limit=200)}

    # ================================================================ ADMIN: users
    admin = auth("admin")

    @app.get("/admin/users")
    def list_users(caller=Depends(admin)):
        return {"users": db.list_users()}

    @app.post("/admin/users")
    def create_user(b: UserIn, caller=Depends(admin)):
        if b.role not in ROLES:
            raise HTTPException(422, f"role must be one of {', '.join(ROLES)}")
        if not USERNAME_RE.match(b.username):
            raise HTTPException(422, "username must be 3-32 letters, digits, '.', '_' or '-'")
        if not db.ensure_user(b.username, b.password, b.role):
            raise HTTPException(409, "username already exists")
        log(caller["username"], "user.create", user=b.username, role=b.role)
        return {"username": b.username, "role": b.role}

    @app.post("/admin/users/{username}/role")
    def set_role(username: str, b: RoleIn, caller=Depends(admin)):
        if b.role not in ROLES:
            raise HTTPException(422, f"role must be one of {', '.join(ROLES)}")
        u = db.get_user(username)
        if not u:
            raise HTTPException(404, "no such user")
        if u["role"] == "admin" and b.role != "admin" and db.count_role("admin") <= 1:
            raise HTTPException(409, "cannot demote the last administrator")
        db.set_role(username, b.role)
        log(caller["username"], "user.role", user=username, role=b.role)
        return {"username": username, "role": b.role}

    @app.post("/admin/users/{username}/password")
    def reset_password(username: str, b: PasswordReset, caller=Depends(admin)):
        if not db.set_password(username, b.password):
            raise HTTPException(404, "no such user")
        log(caller["username"], "user.password_reset", user=username)
        return {"status": "ok"}

    @app.delete("/admin/users/{username}")
    def delete_user(username: str, caller=Depends(admin)):
        u = db.get_user(username)
        if not u:
            raise HTTPException(404, "no such user")
        if username == caller["username"]:
            raise HTTPException(409, "you cannot delete your own account")
        if u["role"] == "admin" and db.count_role("admin") <= 1:
            raise HTTPException(409, "cannot delete the last administrator")
        db.delete_user(username)
        log(caller["username"], "user.delete", user=username)
        return {"status": "deleted"}

    # ================================================================ ADMIN: nodes + registry
    @app.get("/admin/nodes")
    def list_nodes(caller=Depends(admin)):
        return {"nodes": [n.to_dict() for n in ledger.nodes]}

    @app.post("/admin/nodes/{node_id}/toggle")
    def toggle_node(node_id: str, caller=Depends(admin)):
        for n in ledger.nodes:
            if n.id == node_id:
                n.online = not n.online
                if n.online:
                    ledger.resync(n)     # a node returning online catches up before serving again
                log(caller["username"], "ledger.toggle_node", node=node_id, online=n.online)
                return {"node": node_id, "online": n.online}
        raise HTTPException(404, "node not found")

    @app.get("/admin/registry")
    def view_registry(caller=Depends(admin)):
        return reg.d   # public keys and document hashes only

    @app.post("/admin/documents")
    def add_doc(b: DocIn, caller=Depends(admin)):
        who = caller["username"]
        try:
            raw = C.b64d(b.content_b64)
        except Exception:
            raise HTTPException(400, "file content is not valid base64")
        try:
            norm = F.normalize_for_intake(raw, b.filename)
        except F.UnsupportedFormat as e:
            raise HTTPException(415, str(e))
        except F.ConversionUnavailable as e:
            raise HTTPException(501, str(e))
        except F.ConversionFailed as e:
            raise HTTPException(422, str(e))
        stored = norm["stored"]
        doc_hash = C.sha3(stored)
        did = reg.add_document(b.title, doc_hash, who)
        db.store_document(did, b.title, stored, who, norm["kind"], norm["source_kind"], b.filename)   # AES-256-GCM at rest
        log(who, "document.register", document_id=did, hash=doc_hash, source=norm["source_kind"])
        return {"document_id": did, "original_hash": doc_hash, "title": b.title, "kind": norm["kind"],
                "source_kind": norm["source_kind"], "converted": norm["source_kind"] != norm["kind"]}

    @app.get("/formats")
    def formats_info():
        return {"supported": F.SUPPORTED_TEXT, "office_conversion": bool(F.soffice())}

    @app.get("/admin/documents")
    def list_docs(caller=Depends(auth("admin", "submitter", "auditor"))):
        return {"documents": db.list_documents()}

    @app.post("/admin/recipients")
    def add_recipient(b: RecipIn, caller=Depends(admin)):
        kid = reg.add_recipient(b.user_id, b.display_name, b.kem_pk, b.dsa_pk)
        db.add_recipient(kid, b.user_id, b.display_name, b.kem_pk, b.dsa_pk)
        log(caller["username"], "recipient.register", key_id=kid, user_id=b.user_id)
        return {"recipient_key_id": kid}

    @app.get("/admin/recipients")
    def list_recipients(caller=Depends(admin)):
        return {"recipients": db.list_recipients()}

    @app.post("/admin/recipients/{key_id}/revoke")
    def revoke_recipient(key_id: str, caller=Depends(admin)):
        if not reg.recipient(key_id):
            raise HTTPException(404, "unknown key id")
        reg.revoke(key_id)
        db.revoke_recipient(key_id)
        log(caller["username"], "recipient.revoke", key_id=key_id)
        return {"status": "revoked", "key_id": key_id}

    @app.post("/admin/distributions")
    def distribute(b: DistIn, caller=Depends(admin)):
        who = caller["username"]
        doc = reg.document(b.document_id)
        if not doc or doc.get("status") != "active":
            raise HTTPException(404, "unknown or inactive document")
        keys = {}
        for k in b.recipient_key_ids:
            r = reg.recipient(k)
            if not r or r.get("status") != "active":
                raise HTTPException(400, f"recipient {k} not active")
            keys[k] = C.b64d(r["kem_pk"])
        raw = db.get_document_content(b.document_id)
        if not raw:
            raise HTTPException(500, "could not retrieve encrypted document content")
        pkg = package.create_package(raw, b.document_id, doc["title"], keys)
        dist_id = f"DIST-{int(time.time())}-{secrets.token_hex(3)}"
        recipient_pkgs = {k: package.for_recipient(pkg, k) for k in keys}
        db.store_distribution(dist_id, b.document_id, who, recipient_pkgs)
        log(who, "distribution.create", distribution_id=dist_id, document_id=b.document_id, recipients=list(keys))
        return {"distribution_id": dist_id, "packages": recipient_pkgs}

    @app.get("/admin/audit")
    def admin_audit(caller=Depends(admin)):
        return {"verified": db.verify_audit_log(), "entries": db.get_audit_log(limit=200)}

    # ================================================================ Controlled-document release (submitters)
    @app.get("/recipient/packages")
    def recipient_packages(caller=Depends(auth("submitter", "admin"))):
        recip = db.get_recipient_by_user(caller["username"])
        if not recip:
            return {"enrolled": False, "packages": []}
        pk = [{k: v for k, v in x.items() if k not in ("package", "package_json")}
              for x in db.get_packages_for_recipient(recip["recipient_key_id"])]
        return {"enrolled": True, "display_name": recip["display_name"], "recipient_key_id": recip["recipient_key_id"], "packages": pk}

    @app.get("/recipient/packages/{document_id}")
    def recipient_package(document_id: str, caller=Depends(auth("submitter", "admin"))):
        recip = db.get_recipient_by_user(caller["username"])
        if not recip:
            raise HTTPException(403, "no recipient profile for this user")
        pkg = db.get_package_by_doc_and_recipient(document_id, recip["recipient_key_id"])
        if not pkg:
            raise HTTPException(404, "no package found for this recipient and document")
        return {"package": pkg}

    @app.post("/recipient/decrypt-and-release")
    def recipient_decrypt(b: RecipientDecryptIn, caller=Depends(auth("submitter"))):
        user = caller["username"]
        recip = db.get_recipient_by_user(user)
        if not recip:
            raise HTTPException(403, "no recipient profile for this user")
        pkg = db.get_package_by_doc_and_recipient(b.document_id, recip["recipient_key_id"])
        if not pkg:
            raise HTTPException(404, "no package found")
        ks = KeyStore.locate(user, keystore_dir)      # TV_KEYSTORE_<USER> env var, else <keystore_dir>/<user>.keys
        if ks is None:
            raise HTTPException(400, "no keystore configured for this recipient")
        try:
            ks.unlock(b.keystore_passphrase)
        except Exception:
            raise HTTPException(401, "invalid keystore passphrase")
        steps_log = []
        def on_prog(step, status):
            steps_log.append({"step": step, "status": status, "time": time.time()})
        try:
            rel = decrypt_and_release(pkg, ks, ledger, reg, on_prog)
        except ReleaseDenied as e:
            log(user, "recipient.release_denied", document_id=b.document_id, step=e.step)
            return JSONResponse(status_code=409, content={"detail": str(e), "step": e.step, "steps": steps_log})
        log(user, "recipient.decrypt_and_release", session_id=rel.event["session_id"], document_id=b.document_id)
        import pymupdf
        content = rel.protected_pdf
        is_pdf = content[:5] == b"%PDF-"
        if is_pdf:
            doc = pymupdf.open(stream=content, filetype="pdf")
            page_images = [C.b64e(p.get_pixmap(dpi=150).tobytes("jpeg")) for p in doc]
        else:
            page_images = [C.b64e(content)]
        meta = db.get_document_meta(b.document_id) or {}
        return {"session_id": rel.event["session_id"], "watermark_digest": rel.event["watermark_digest"],
                "record": rel.record, "steps": steps_log, "protected_b64": C.b64e(content),
                "protected_pdf_b64": C.b64e(content) if is_pdf else None,
                "media_type": "application/pdf" if is_pdf else "image/png", "extension": "pdf" if is_pdf else "png",
                "image_media_type": "image/jpeg" if is_pdf else "image/png",
                "source_kind": meta.get("source_kind", "pdf"), "page_images": page_images}

    @app.post("/ledger/commit")
    def commit(b: CommitIn, caller=Depends(auth("submitter", "admin"))):
        try:
            rec = ledger.commit(b.event, C.b64d(b.signature), b.signer_key_id, reg)
        except Exception as e:
            raise HTTPException(409, str(e))
        log(caller["username"], "ledger.commit", session_id=b.event.get("session_id"))
        return rec

    @app.get("/ledger/status")
    def status(caller=Depends(auth("admin", "auditor"))):
        v = ledger.verify(reg)
        v["nodes_summary"] = [n.to_dict() for n in ledger.nodes]
        return v

    # ================================================================ Recipient enrolment
    def enroll(user: str, display_name: str, passphrase: str, actor: str) -> dict:
        """Create a passphrase-encrypted ML-KEM/ML-DSA keystore and register its public keys for `user`."""
        if not db.get_user(user):
            raise HTTPException(404, "no such user")
        if any(r["user_id"] == user for r in db.list_recipients()):
            raise HTTPException(409, "this account already has a recipient profile (ask an administrator to change it)")
        path = os.path.join(keystore_dir, f"{user}.keys")
        if os.path.exists(path) or KeyStore.from_env(user):
            raise HTTPException(409, "a keystore already exists for this account")
        os.makedirs(keystore_dir, exist_ok=True)
        pub = KeyStore.create(path, passphrase).public
        kid = reg.add_recipient(user, display_name, pub["kem_pk"], pub["dsa_pk"])
        db.add_recipient(kid, user, display_name, pub["kem_pk"], pub["dsa_pk"])
        log(actor, "recipient.enroll", key_id=kid, user_id=user)
        return {"recipient_key_id": kid, "display_name": display_name}

    @app.post("/recipient/enroll")
    def enroll_self(b: EnrollIn, caller=Depends(auth("submitter"))):
        return enroll(caller["username"], b.display_name, b.passphrase, caller["username"])

    @app.post("/admin/recipients/enroll")
    def enroll_for(b: AdminEnrollIn, caller=Depends(admin)):
        return enroll(b.user_id, b.display_name, b.passphrase, caller["username"])

    # ================================================================ Security tests (run on throw-away copies)
    sim_roles = auth("auditor", "admin")

    @app.post("/simulate/{kind}")
    def simulate(kind: str, caller=Depends(sim_roles)):
        """Real attacks against *copies* of the ledger/registry; live data is never modified."""
        steps, defended = [], False
        def add(text, ok=True): steps.append({"text": text, "ok": ok})
        if kind not in ("tamper_ledger", "key_substitution", "quorum_loss"):
            raise HTTPException(404, "unknown test")
        exp = copy.deepcopy(ledger.export_chain())
        if not exp["nodes"]["node-1"]:
            raise HTTPException(409, "The ledger is empty. Run the demo or open a document first so there is something to attack.")
        if kind == "tamper_ledger":
            title = "Three ledger nodes rewrite history"
            add("Copied the ledger and changed the timestamp of the first record on nodes 1, 2 and 3.")
            for nid in ("node-1", "node-2", "node-3"):
                exp["nodes"][nid][0]["event"]["timestamp"] = "2000-01-01T00:00:00Z"
            v = verify_export(exp, copy.deepcopy(reg.d))
            for nid, n in v["nodes"].items():
                add(f"{nid.replace('node-', 'Node ')}: " + ("copy is valid" if n["valid"] else "tampering detected — " + n["errors"][0]), n["valid"] is False or nid == "node-4")
            defended = not v["verified"]
            result = "The altered majority was detected and rejected." if defended else "The tampering was NOT detected."
        elif kind == "key_substitution":
            title = "An attacker swaps a recipient's public key"
            r = copy.deepcopy(reg.d)
            kid = exp["nodes"]["node-1"][0]["signer_key_id"]
            r["recipients"][kid]["dsa_pk"] = C.b64e(C.dsa_keygen()[0])
            add(f"Replaced the registered signing key of {r['recipients'][kid]['display_name']} with the attacker's key (copy only).")
            v = verify_export(exp, r)
            add("Re-verified every ledger record against the altered registry.")
            for nid, n in v["nodes"].items():
                add(f"{nid.replace('node-', 'Node ')}: " + ("accepted" if n["valid"] else "rejected — " + n["errors"][0]), not n["valid"])
            defended = not v["verified"]
            result = "The substituted key failed signature checks everywhere." if defended else "The substitution was NOT detected."
        else:
            title = "Two of four ledger nodes go offline"
            tmp = tempfile.mkdtemp(prefix="tv_sim_")
            try:
                dst = os.path.join(tmp, "ledger")
                shutil.copytree(os.path.join(data_dir, "ledger"), dst, ignore=shutil.ignore_patterns("*.lock"))
                sim = _Ledger(dst)
                sim.nodes[0].online = sim.nodes[1].online = False
                add("Copied the ledger and took nodes 1 and 2 offline (2 of 4 online; 3 are required).")
                t_reg = Registry()
                ks = KeyStore.create(os.path.join(tmp, "k.keys"), "x" * 12).unlock("x" * 12)
                t_pub = ks.public
                t_kid = t_reg.add_recipient("sim", "Simulated", t_pub["kem_pk"], t_pub["dsa_pk"])
                ev = events.new_event("D-SIM", t_kid, C.sha3(b"sim"))
                add("A recipient tries to record a new document release…")
                try:
                    sim.commit(ev, ks.sign(C.event_message(ev)), t_kid, t_reg)
                    add("The release was recorded — the quorum rule did NOT hold.", False)
                except RuntimeError as e:
                    add(f"Blocked: {e}")
                    defended = True
                result = "Release is refused when fewer than 3 nodes can attest (fail-closed)." if defended else "Quorum rule failed."
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        add("Your real ledger and registry were not changed.")
        log(caller["username"], "simulate." + kind, defended=defended)
        return {"kind": kind, "title": title, "defended": defended, "result": result, "steps": steps}

    # ================================================================ Golden path (real, end to end)
    @app.post("/admin/demo/golden-path")
    def golden_path(caller=Depends(admin)):
        """Runs the whole story for real with throw-away demo recipients: register a document, share it with
        three people, one opens it (watermark + signature + ledger), the copy 'leaks', and is traced back."""
        from .sample import sample_pdf
        import pymupdf
        who, steps = caller["username"], []
        def add(text): steps.append({"text": text, "ok": True})
        tmp = tempfile.mkdtemp(prefix="tv_demo_")
        run, kids, keystores = uuid.uuid4().hex[:4], [], []
        try:
            for i, nm in enumerate(("Alice Morgan", "Bob Rivera", "Charlie Osei")):
                pw = secrets.token_urlsafe(12)
                ks = KeyStore.create(os.path.join(tmp, f"{i}.keys"), pw).unlock(pw); pub = ks.public
                uid = f"demo-{nm.split()[0].lower()}-{run}"
                kid = reg.add_recipient(uid, f"Demo · {nm}", pub["kem_pk"], pub["dsa_pk"])
                db.add_recipient(kid, uid, f"Demo · {nm}", pub["kem_pk"], pub["dsa_pk"])
                kids.append(kid); keystores.append(ks)
            add("Registered three demo recipients, each with their own post-quantum keys.")
            pdf = sample_pdf(pages=2)
            did = reg.add_document(f"Demo · Operation Plan ({run})", C.sha3(pdf), who)
            db.store_document(did, f"Demo · Operation Plan ({run})", pdf, who)
            add("Stored a classified PDF in the encrypted vault.")
            pkg = package.create_package(pdf, did, "Demo", {k: C.b64d(reg.recipient(k)["kem_pk"]) for k in kids})
            dist = f"DIST-DEMO-{run}"
            db.store_distribution(dist, did, who, {k: package.for_recipient(pkg, k) for k in kids})
            add("Shared it with all three: one encrypted file, a separate lock for each person.")
            rel = decrypt_and_release(package.for_recipient(pkg, kids[1]), keystores[1], ledger, reg)
            add(f"Bob opened it. His copy got an invisible tracking mark, he signed the event, and the ledger recorded it as block #{rel.record['index']} with {len(rel.record['attestations'])} of 4 node approvals.")
            doc = pymupdf.open(stream=rel.protected_pdf, filetype="pdf")
            doc.set_metadata({**doc.metadata, "author": "unknown"})
            leak = doc.tobytes(deflate=True)
            add("The document leaked: someone re-saved it and stripped its metadata.")
            rep = evidence.process_case(leak, "leaked_copy.pdf", reg, ledger, evidence_dir, who)
            rep["case_id"] += "-" + uuid.uuid4().hex[:4]
            db.store_evidence_case(rep["case_id"], rep["evidence_file"], rep["evidence_sha3_256"], who, rep["status"], rep)
            who_is = (rep.get("match") or {}).get("recipient")
            add(f"The leaked file was checked: {evidence.verdict(rep['status'])['headline']}" + (f". Traced to {who_is}." if who_is else "."))
            for k in kids:                    # throw-away recipients: keep the history, close the door
                reg.revoke(k); db.revoke_recipient(k)
            log(who, "demo.golden_path", case_id=rep["case_id"], status=rep["status"])
            return {"steps": steps, "case": {"case_id": rep["case_id"], "filename": rep["evidence_file"], "status": rep["status"],
                    "date": rep["submitted_at"], "submitter": who, **evidence.verdict(rep["status"])}, "traced_to": who_is}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ================================================================ UI shell (static HTML only)
    ui_path = os.path.join(os.path.dirname(__file__), "web", "index.html")

    @app.get("/", response_class=HTMLResponse)
    @app.get("/app", response_class=HTMLResponse)
    def serve_ui():
        if os.path.exists(ui_path):
            return FileResponse(ui_path)
        return HTMLResponse("<h2>TraceVault UI not found</h2>", status_code=404)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app
