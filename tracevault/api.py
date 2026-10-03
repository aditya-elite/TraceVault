"""FastAPI orchestration with backend-enforced roles, persistent database, and encrypted storage.
The API strictly rejects any private-key fields in schemas (PRD §6, §23).
"""
import base64, hashlib, hmac, json, os, time
from fastapi import Depends, FastAPI, HTTPException, Header, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, ConfigDict
from . import crypto as C, package, evidence, watermark as W, events
from .db import Database
from .keystore import KeyStore
from .ledger import Ledger
from .registry import Registry
from .release import decrypt_and_release
from .report_pdf import generate_report_pdf

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

class Login(Strict):
    username: str
    password: str

class DocIn(Strict):
    title: str
    content_b64: str

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

class CaseIn(Strict):
    filename: str
    content_b64: str

class RecipientDecryptIn(Strict):
    document_id: str
    keystore_passphrase: str

def create_app(data_dir: str, users: dict | None = None, secret: bytes | None = None) -> FastAPI:
    """Creates the production-grade TraceVault FastAPI application."""
    os.makedirs(data_dir, exist_ok=True)
    
    # Persistent master secrets
    secret_path = os.path.join(data_dir, "api_secret.key")
    if secret:
        app_secret = secret
    elif os.path.exists(secret_path):
        app_secret = open(secret_path, "rb").read()
    else:
        app_secret = os.urandom(32)
        with open(secret_path, "wb") as f:
            f.write(app_secret)
        try:
            os.chmod(secret_path, 0o600)
        except Exception:
            pass

    # Persistent SQLite DB
    db = Database(os.path.join(data_dir, "tracevault.db"))
    
    # Initialize Registry and Ledger
    reg = Registry(os.path.join(data_dir, "registry.json"))
    ledger = Ledger(os.path.join(data_dir, "ledger"))
    
    # Seed users if provided
    if users:
        for u, v in users.items():
            db.add_user(u, v["password"], v["role"])
            
    app = FastAPI(title="TraceVault", version="2.0.0")
    app.state.db = db
    app.state.registry = reg
    app.state.ledger = ledger
    app.state.data_dir = data_dir

    def log(actor, action, **kw):
        db.append_audit(actor, action, **kw)

    def mint(user, role):
        body = C.b64e(json.dumps({"u": user, "r": role, "exp": time.time() + 86400}).encode())
        return body + "." + hmac.new(app_secret, body.encode(), "sha256").hexdigest()

    def auth(*roles):
        def dep(authorization: str = Header(default="")):
            try:
                body, mac = authorization.removeprefix("Bearer ").split(".")
                if not hmac.compare_digest(mac, hmac.new(app_secret, body.encode(), "sha256").hexdigest()):
                    raise ValueError
                t = json.loads(C.b64d(body))
                if t["exp"] < time.time():
                    raise ValueError
            except Exception:
                raise HTTPException(401, "invalid or missing token")
            if t["r"] not in roles:
                raise HTTPException(403, f"role '{t['r']}' not permitted")
            return {"username": t["u"], "role": t["r"]}
        return dep

    # --- Authentication ---
    @app.post("/auth/login")
    def login(b: Login):
        u = db.verify_user(b.username, b.password)
        if not u:
            raise HTTPException(401, "bad credentials")
        log(b.username, "login", role=u["role"])
        recip = db.get_recipient_by_user(b.username)
        return {
            "token": mint(b.username, u["role"]),
            "role": u["role"],
            "username": b.username,
            "recipient_key_id": recip["recipient_key_id"] if recip else None
        }

    # --- Admin: Documents (Encrypted at Rest) ---
    @app.post("/admin/documents")
    def add_doc(b: DocIn, caller=Depends(auth("admin"))):
        who = caller["username"]
        raw = C.b64d(b.content_b64)
        if raw[:5] != b"%PDF-":
            raise HTTPException(400, "PDF required")
        doc_hash = C.sha3(raw)
        did = reg.add_document(b.title, doc_hash, who)
        # Store encrypted at rest in DB vault
        db.store_document(did, b.title, raw, who)
        log(who, "document.register", document_id=did, hash=doc_hash)
        return {"document_id": did, "original_hash": doc_hash, "title": b.title}

    @app.get("/admin/documents")
    def list_docs(caller=Depends(auth("admin", "recipient", "investigator"))):
        return {"documents": db.list_documents()}

    # --- Admin: Recipients ---
    @app.post("/admin/recipients")
    def add_recipient(b: RecipIn, caller=Depends(auth("admin"))):
        who = caller["username"]
        kid = reg.add_recipient(b.user_id, b.display_name, b.kem_pk, b.dsa_pk)
        db.add_recipient(kid, b.user_id, b.display_name, b.kem_pk, b.dsa_pk)
        log(who, "recipient.register", key_id=kid, user_id=b.user_id)
        return {"recipient_key_id": kid}

    @app.get("/admin/recipients")
    def list_recipients(caller=Depends(auth("admin", "investigator", "recipient"))):
        return {"recipients": db.list_recipients()}

    @app.post("/admin/recipients/{key_id}/revoke")
    def revoke_recipient(key_id: str, caller=Depends(auth("admin"))):
        reg.revoke(key_id)
        db.revoke_recipient(key_id)
        log(caller["username"], "recipient.revoke", key_id=key_id)
        return {"status": "revoked", "key_id": key_id}

    # --- Admin: Distributions ---
    @app.post("/admin/distributions")
    def distribute(b: DistIn, caller=Depends(auth("admin"))):
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
        dist_id = f"DIST-{int(time.time())}"
        recipient_pkgs = {k: package.for_recipient(pkg, k) for k in keys}
        db.store_distribution(dist_id, b.document_id, who, recipient_pkgs)
        log(who, "distribution.create", distribution_id=dist_id, document_id=b.document_id, recipients=list(keys))
        return {"distribution_id": dist_id, "packages": recipient_pkgs}

    # --- Recipient Flow ---
    @app.get("/recipient/packages")
    def recipient_packages(caller=Depends(auth("recipient", "admin"))):
        user = caller["username"]
        recip = db.get_recipient_by_user(user)
        if not recip:
            return {"packages": []}
        pkgs = db.get_packages_for_recipient(recip["recipient_key_id"])
        return {"recipient_key_id": recip["recipient_key_id"], "packages": pkgs}

    @app.get("/recipient/packages/{document_id}")
    def recipient_package(document_id: str, caller=Depends(auth("recipient", "admin"))):
        user = caller["username"]
        recip = db.get_recipient_by_user(user)
        if not recip:
            raise HTTPException(403, "no recipient profile for this user")
        pkg = db.get_package_by_doc_and_recipient(document_id, recip["recipient_key_id"])
        if not pkg:
            raise HTTPException(404, "no package found for this recipient and document")
        return {"package": pkg}

    @app.post("/recipient/decrypt-and-release")
    def recipient_decrypt(b: RecipientDecryptIn, caller=Depends(auth("recipient"))):
        user = caller["username"]
        recip = db.get_recipient_by_user(user)
        if not recip:
            raise HTTPException(403, "no recipient profile for this user")
        kid = recip["recipient_key_id"]
        pkg = db.get_package_by_doc_and_recipient(b.document_id, kid)
        if not pkg:
            raise HTTPException(404, "no package found")
            
        keystore_path = os.path.join(data_dir, f"{user}.keys")
        if not os.path.exists(keystore_path):
            raise HTTPException(400, "local keystore not found for this recipient")
        try:
            ks = KeyStore(keystore_path).unlock(b.keystore_passphrase)
        except Exception:
            raise HTTPException(401, "invalid keystore passphrase")

        steps_log = []
        def on_prog(step, status):
            steps_log.append({"step": step, "status": status, "time": time.time()})

        rel = decrypt_and_release(pkg, ks, ledger, reg, on_prog)
        log(user, "recipient.decrypt_and_release", session_id=rel.event["session_id"], document_id=b.document_id)
        
        import pymupdf
        doc = pymupdf.open(stream=rel.protected_pdf, filetype="pdf")
        page_images = []
        for p in doc:
            pm = p.get_pixmap(dpi=150)
            page_images.append(C.b64e(pm.tobytes("jpeg")))

        return {
            "session_id": rel.event["session_id"],
            "watermark_digest": rel.event["watermark_digest"],
            "record": rel.record,
            "steps": steps_log,
            "protected_pdf_b64": C.b64e(rel.protected_pdf),
            "page_images": page_images
        }

    # --- Ledger Endpoints ---
    @app.post("/ledger/commit")
    def commit(b: CommitIn, caller=Depends(auth("recipient", "admin"))):
        try:
            rec = ledger.commit(b.event, C.b64d(b.signature), b.signer_key_id, reg)
        except Exception as e:
            raise HTTPException(409, str(e))
        log(caller["username"], "ledger.commit", session_id=b.event.get("session_id"))
        return rec

    @app.get("/ledger/status")
    def status(caller=Depends(auth("admin", "investigator", "recipient"))):
        v = ledger.verify(reg)
        v["nodes_summary"] = [n.to_dict() for n in ledger.nodes]
        return v

    @app.get("/ledger/export")
    def export_ledger(caller=Depends(auth("admin", "investigator"))):
        return {
            "ledger": ledger.export_chain(),
            "registry": reg.d
        }

    @app.post("/ledger/nodes/{node_id}/toggle")
    def toggle_node(node_id: str, caller=Depends(auth("admin"))):
        for n in ledger.nodes:
            if n.id == node_id:
                n.online = not n.online
                log(caller["username"], "ledger.toggle_node", node=node_id, online=n.online)
                return {"node": node_id, "online": n.online}
        raise HTTPException(404, "node not found")

    # --- Investigator: Evidence & Verification ---
    @app.post("/investigator/cases")
    def case(b: CaseIn, caller=Depends(auth("investigator", "admin"))):
        who = caller["username"]
        raw = C.b64d(b.content_b64)
        evidence_dir = os.path.join(data_dir, "evidence")
        rep = evidence.process_case(raw, b.filename, reg, ledger, evidence_dir, who)
        db.store_evidence_case(rep["case_id"], b.filename, rep["evidence_sha3_256"], who, rep["status"], rep)
        log(who, "case.run", case_id=rep["case_id"], status=rep["status"])
        return rep

    @app.get("/investigator/cases")
    def list_cases(caller=Depends(auth("investigator", "admin", "recipient"))):
        return {"cases": db.list_evidence_cases()}

    @app.get("/investigator/cases/{case_id}")
    def get_case(case_id: str, caller=Depends(auth("investigator", "admin"))):
        c = db.get_evidence_case(case_id)
        if not c:
            raise HTTPException(404, "case not found")
        return c

    @app.get("/investigator/cases/{case_id}/pdf")
    def export_case_pdf(case_id: str, caller=Depends(auth("investigator", "admin"))):
        c = db.get_evidence_case(case_id)
        if not c:
            raise HTTPException(404, "case not found")
        pdf_bytes = generate_report_pdf(c["report"])
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=TraceVault_Report_{case_id}.pdf"}
        )

    @app.get("/investigator/cases/{case_id}/json")
    def export_case_json(case_id: str, caller=Depends(auth("investigator", "admin"))):
        c = db.get_evidence_case(case_id)
        if not c:
            raise HTTPException(404, "case not found")
        return JSONResponse(
            content=c["report"],
            headers={"Content-Disposition": f"attachment; filename=TraceVault_Report_{case_id}.json"}
        )

    # --- Audit Log ---
    @app.get("/audit")
    def get_audit(caller=Depends(auth("admin", "investigator"))):
        entries = db.get_audit_log(limit=100)
        valid = db.verify_audit_log()
        return {"verified": valid, "entries": entries}

    # --- Realistic Demo Runner & Seed ---
    @app.post("/demo/seed")
    def demo_seed():
        from .sample import sample_pdf
        # 1. Add Default Users
        users_seed = [
            ("admin", "admin123", "admin"),
            ("alice", "alice123", "recipient"),
            ("bob", "bob123", "recipient"),
            ("charlie", "charlie123", "recipient"),
            ("investigator", "investigator123", "investigator")
        ]
        for u, pw, r in users_seed:
            db.add_user(u, pw, r)

        # 2. Generate Keystores and Register Recipients
        kids = []
        for i, u in enumerate(["alice", "bob", "charlie"]):
            ks_path = os.path.join(data_dir, f"{u}.keys")
            if not os.path.exists(ks_path):
                k = KeyStore.create(ks_path, f"{u}123").unlock(f"{u}123")
            else:
                k = KeyStore(ks_path).unlock(f"{u}123")
            p = k.public
            kid = reg.add_recipient(u, f"Recipient {u.capitalize()}", p["kem_pk"], p["dsa_pk"])
            db.add_recipient(kid, u, f"Recipient {u.capitalize()}", p["kem_pk"], p["dsa_pk"])
            kids.append((kid, k))

        # 3. Create sample document
        sample_doc = sample_pdf(pages=2)
        did = reg.add_document("SIH Classified Operation Plan", C.sha3(sample_doc), "admin")
        db.store_document(did, "SIH Classified Operation Plan", sample_doc, "admin")

        # 4. Create multi-recipient distribution
        keys = {kid: C.b64d(reg.recipient(kid)["kem_pk"]) for kid, _ in kids}
        pkg = package.create_package(sample_doc, did, "SIH Classified Operation Plan", keys)
        dist_id = "DIST-DEMO-001"
        recip_pkgs = {kid: package.for_recipient(pkg, kid) for kid in keys}
        db.store_distribution(dist_id, did, "admin", recip_pkgs)

        log("system", "demo.seed_completed", document_id=did, recipients=[k[0] for k in kids])
        return {
            "status": "success",
            "document_id": did,
            "recipients": [{"user": u, "kid": kid} for u, (kid, _) in zip(["alice", "bob", "charlie"], kids)]
        }

    # --- UI Web Route ---
    @app.get("/", response_class=HTMLResponse)
    @app.get("/app", response_class=HTMLResponse)
    def serve_ui():
        ui_path = os.path.join(os.path.dirname(__file__), "web", "index.html")
        if os.path.exists(ui_path):
            return FileResponse(ui_path)
        return HTMLResponse("<h2>TraceVault UI loading...</h2>")

    return app
