import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

import jwt
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Requirement as RequirementSchema, Estimate as EstimateSchema, PO as POSchema, AuditLog as AuditLogSchema

# ----------------------------------------------------------------------------
# App setup
# ----------------------------------------------------------------------------
app = FastAPI(title="SaaSOTY v1 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------------------
# Auth & Security
# ----------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

security = HTTPBearer()
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str
    assigned_ae_id: Optional[str] = None


class EstimateCreateRequest(BaseModel):
    requirement_id: str
    amount: float
    currency: str = "USD"
    breakdown: Dict[str, Any] = {}
    notes: Optional[str] = None


class ClientActionRequest(BaseModel):
    action: str  # "good_to_go" | "request_call"


class VerifyPORequest(BaseModel):
    decision: str  # "verified" | "rejected"
    notes: Optional[str] = None


# ----------------------------------------------------------------------------
# Utility helpers
# ----------------------------------------------------------------------------

def hash_password(p: str) -> str:
    return password_context.hash(p)


def verify_password(p: str, hashed: str) -> bool:
    return password_context.verify(p, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        # Try by ObjectId
        user = None
        if ObjectId.is_valid(user_id):
            user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            user = db["user"].find_one({"_id": user_id})
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not user:
        raise HTTPException(status_code=401, detail="User not found for token")
    user["id"] = str(user.get("_id"))
    return user


def require_role(user: dict, allowed: List[str]):
    if user.get("role") not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden")


def notify_email(to_email: str, subject: str, body: str):
    # Stub notification - in real deployment integrate SMTP provider
    print(f"[Email] To:{to_email} | Subject:{subject} | Body:{body[:200]}")


def add_audit(entity: str, entity_id: str, action: str, actor_id: str, meta: Dict[str, Any] | None = None):
    log = AuditLogSchema(entity=entity, entity_id=entity_id, action=action, actor_id=actor_id, meta=meta or {})
    create_document("auditlog", log)


def get_next_ae_id() -> Optional[str]:
    aes = list(db["user"].find({"role": "ae"}).sort("_id", 1))
    if not aes:
        return None
    settings = db["app_settings"].find_one({"_id": "round_robin"})
    if not settings:
        settings = {"_id": "round_robin", "index": 0}
        db["app_settings"].insert_one(settings)
    index = settings.get("index", 0) % len(aes)
    ae = aes[index]
    db["app_settings"].update_one({"_id": "round_robin"}, {"$set": {"index": (index + 1) % len(aes)}})
    return str(ae.get("_id"))


# ----------------------------------------------------------------------------
# Basic routes
# ----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"name": "SaaSOTY v1 API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "✅ Connected" if db is not None else "❌ Not Available",
        "collections": db.list_collection_names() if db is not None else [],
    }
    return response


# ----------------------------------------------------------------------------
# Seed demo users (idempotent for demo/testing)
# ----------------------------------------------------------------------------
@app.post("/seed")
def seed():
    def ensure_user(name: str, email: str, role: str, password: str, assigned_ae_id: Optional[str] = None):
        u = db["user"].find_one({"email": email})
        hashed = hash_password(password)
        if u:
            # Ensure role, assigned AE, and reset password for demo stability
            updates: Dict[str, Any] = {
                "role": role,
                "password_hash": hashed,
            }
            if assigned_ae_id is not None:
                updates["assigned_ae_id"] = assigned_ae_id
            db["user"].update_one({"_id": u.get("_id")}, {"$set": updates})
            return str(u.get("_id"))
        doc = UserSchema(name=name, email=email, password_hash=hashed, role=role, assigned_ae_id=assigned_ae_id).model_dump()
        return create_document("user", doc)

    ae_id = ensure_user("Alex AE", "ae@saasoty.io", "ae", "password123")
    client_id = ensure_user("Cathy Client", "client@saasoty.io", "client", "password123", assigned_ae_id=ae_id)
    verifier_id = ensure_user("Vik Verifier", "verifier@saasoty.io", "verifier", "password123")
    admin_id = ensure_user("Ada Admin", "admin@saasoty.io", "admin", "password123")

    return {"ae_id": ae_id, "client_id": client_id, "verifier_id": verifier_id, "admin_id": admin_id}


# ----------------------------------------------------------------------------
# Auth routes
# ----------------------------------------------------------------------------
@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user.get("_id")), "email": user["email"], "role": user.get("role")})
    user_out = {k: user[k] for k in ["name", "email", "role"] if k in user}
    user_out["id"] = str(user.get("_id"))
    user_out["assigned_ae_id"] = user.get("assigned_ae_id")
    return TokenResponse(access_token=token, user=user_out)


@app.post("/auth/register")
def register(payload: RegisterRequest, current=Depends(get_current_user)):
    require_role(current, ["admin"])
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    hashed = hash_password(payload.password)
    user_doc = UserSchema(
        name=payload.name, email=payload.email, password_hash=hashed, role=payload.role, assigned_ae_id=payload.assigned_ae_id
    ).model_dump()
    new_id = create_document("user", user_doc)
    add_audit("user", new_id, "created", current["id"], {"email": payload.email, "role": payload.role})
    return {"id": new_id}


# ----------------------------------------------------------------------------
# Requirement routes
# ----------------------------------------------------------------------------
@app.post("/requirements")
def create_requirement(
    type: str = Form(...),
    subtype: Optional[str] = Form(None),
    details: str = Form(...),
    attachment: Optional[UploadFile] = File(None),
    current=Depends(get_current_user),
):
    require_role(current, ["client", "admin"])
    if type not in ["hardware", "software"]:
        raise HTTPException(status_code=400, detail="Invalid type")
    if type == "software" and subtype not in ["new", "renewal", "upgrade"]:
        raise HTTPException(status_code=400, detail="Invalid subtype for software")

    ae_id = current.get("assigned_ae_id") or get_next_ae_id()

    attach_list: List[Dict[str, Any]] = []
    if attachment is not None:
        attach_list.append({"filename": attachment.filename, "content_type": attachment.content_type})

    # Parse details JSON string
    try:
        import json
        details_payload = json.loads(details) if isinstance(details, str) else details
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid details JSON")

    req = RequirementSchema(
        client_id=current.get("id") or str(current.get("_id")),
        ae_id=ae_id,
        type=type,
        subtype=subtype,
        details=details_payload,
        attachments=attach_list,
        status="pending_ae_estimate",
    )
    rid = create_document("requirement", req)
    add_audit("requirement", rid, "created", current.get("id") or str(current.get("_id")))

    # notify AE
    if ae_id:
        ae_doc = None
        if ObjectId.is_valid(ae_id):
            ae_doc = db["user"].find_one({"_id": ObjectId(ae_id)})
        if not ae_doc:
            ae_doc = db["user"].find_one({"_id": ae_id})
        if ae_doc:
            notify_email(ae_doc.get("email", ""), "New requirement assigned", f"Requirement {rid} has been assigned to you.")

    return {"id": rid, "status": "pending_ae_estimate"}


@app.get("/requirements")
def list_requirements(status: Optional[str] = None, current=Depends(get_current_user)):
    query: Dict[str, Any] = {}
    role = current.get("role")
    uid = current.get("id") or str(current.get("_id"))
    if role == "client":
        query["client_id"] = uid
    elif role == "ae":
        query["ae_id"] = uid
    elif role in ["verifier", "admin"]:
        pass
    else:
        raise HTTPException(status_code=403, detail="Forbidden")
    if status:
        query["status"] = status
    items = get_documents("requirement", query, limit=None)
    for it in items:
        it["id"] = str(it.get("_id"))
    return items


@app.get("/requirements/{rid}")
def get_requirement(rid: str, current=Depends(get_current_user)):
    doc = None
    if ObjectId.is_valid(rid):
        doc = db["requirement"].find_one({"_id": ObjectId(rid)})
    if not doc:
        doc = db["requirement"].find_one({"_id": rid})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    role = current.get("role")
    uid = current.get("id") or str(current.get("_id"))
    if role == "client" and doc.get("client_id") != uid:
        raise HTTPException(status_code=403, detail="Forbidden")
    if role == "ae" and doc.get("ae_id") != uid:
        raise HTTPException(status_code=403, detail="Forbidden")
    doc["id"] = str(doc.get("_id"))
    return doc


# ----------------------------------------------------------------------------
# Estimate routes (AE)
# ----------------------------------------------------------------------------
@app.post("/estimates")
def create_estimate(payload: EstimateCreateRequest, current=Depends(get_current_user)):
    require_role(current, ["ae", "admin"])
    req = None
    if ObjectId.is_valid(payload.requirement_id):
        req = db["requirement"].find_one({"_id": ObjectId(payload.requirement_id)})
    if not req:
        req = db["requirement"].find_one({"_id": payload.requirement_id})
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")
    uid = current.get("id") or str(current.get("_id"))
    if current.get("role") == "ae" and req.get("ae_id") != uid:
        raise HTTPException(status_code=403, detail="Not your assignment")

    est = EstimateSchema(
        requirement_id=str(req.get("_id")),
        ae_id=uid,
        amount=payload.amount,
        currency=payload.currency,
        breakdown=payload.breakdown,
        notes=payload.notes,
        status="sent",
    )
    eid = create_document("estimate", est)

    db["requirement"].update_one({"_id": req.get("_id")}, {"$set": {"status": "awaiting_client_decision"}})

    client = db["user"].find_one({"_id": req.get("client_id")}) or (
        db["user"].find_one({"_id": ObjectId(req.get("client_id"))}) if ObjectId.is_valid(req.get("client_id", "")) else None
    )
    if client:
        notify_email(client.get("email", ""), "Estimate uploaded", f"An estimate for requirement {str(req.get("_id"))} is available.")
    add_audit("estimate", eid, "created", uid, {"requirement_id": str(req.get("_id"))})
    return {"id": eid}


# ----------------------------------------------------------------------------
# Client actions post-estimate
# ----------------------------------------------------------------------------
@app.post("/requirements/{rid}/client-action")
def requirement_client_action(rid: str, payload: ClientActionRequest, current=Depends(get_current_user)):
    require_role(current, ["client", "admin"])
    req = None
    if ObjectId.is_valid(rid):
        req = db["requirement"].find_one({"_id": ObjectId(rid)})
    if not req:
        req = db["requirement"].find_one({"_id": rid})
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")
    uid = current.get("id") or str(current.get("_id"))
    if current.get("role") == "client" and req.get("client_id") != uid:
        raise HTTPException(status_code=403, detail="Forbidden")
    if payload.action == "good_to_go":
        db["requirement"].update_one({"_id": req.get("_id")}, {"$set": {"status": "client_good_to_go"}})
        ae = db["user"].find_one({"_id": req.get("ae_id")}) or (
            db["user"].find_one({"_id": ObjectId(req.get("ae_id"))}) if ObjectId.is_valid(req.get("ae_id", "")) else None
        )
        if ae:
            notify_email(ae.get("email", ""), "Client Good to Go", f"Requirement {rid} marked Good to Go.")
        add_audit("requirement", str(req.get("_id")), "client_good_to_go", uid)
    elif payload.action == "request_call":
        db["requirement"].update_one({"_id": req.get("_id")}, {"$set": {"status": "client_requested_call"}})
        ae = db["user"].find_one({"_id": req.get("ae_id")}) or (
            db["user"].find_one({"_id": ObjectId(req.get("ae_id"))}) if ObjectId.is_valid(req.get("ae_id", "")) else None
        )
        if ae:
            notify_email(ae.get("email", ""), "Client requested a call", f"Please contact client for requirement {rid}.")
        add_audit("requirement", str(req.get("_id")), "client_requested_call", uid)
    else:
        raise HTTPException(status_code=400, detail="Invalid action")
    return {"ok": True}


# ----------------------------------------------------------------------------
# PO submission (Client)
# ----------------------------------------------------------------------------
@app.post("/requirements/{rid}/po")
async def submit_po(
    rid: str,
    po_number: str = Form(...),
    remarks: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    current=Depends(get_current_user),
):
    require_role(current, ["client", "admin"])
    req = None
    if ObjectId.is_valid(rid):
        req = db["requirement"].find_one({"_id": ObjectId(rid)})
    if not req:
        req = db["requirement"].find_one({"_id": rid})
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")
    uid = current.get("id") or str(current.get("_id"))
    if current.get("role") == "client" and req.get("client_id") != uid:
        raise HTTPException(status_code=403, detail="Forbidden")

    file_url = None
    if file is not None:
        file_url = f"uploaded://{file.filename}"

    po = POSchema(
        requirement_id=str(req.get("_id")),
        po_number=po_number,
        file_url=file_url,
        remarks=remarks,
        status="pending_verification",
    )
    po_id = create_document("po", po)

    db["requirement"].update_one({"_id": req.get("_id")}, {"$set": {"status": "pending_verification"}})

    verifiers = list(db["user"].find({"role": {"$in": ["verifier", "admin"]}}))
    for v in verifiers:
        notify_email(v.get("email", ""), "PO uploaded", f"PO for requirement {str(req.get("_id"))} is pending verification.")

    add_audit("po", po_id, "submitted", uid, {"requirement_id": str(req.get("_id"))})
    return {"id": po_id}


# ----------------------------------------------------------------------------
# Verification (Verifier/Admin)
# ----------------------------------------------------------------------------
@app.get("/pos")
def list_pos(status: Optional[str] = None, current=Depends(get_current_user)):
    require_role(current, ["verifier", "admin"])
    q: Dict[str, Any] = {}
    if status:
        q["status"] = status
    items = get_documents("po", q)
    for it in items:
        it["id"] = str(it.get("_id"))
    return items


@app.post("/pos/{po_id}/review")
def review_po(po_id: str, payload: VerifyPORequest, current=Depends(get_current_user)):
    require_role(current, ["verifier", "admin"])
    po = None
    if ObjectId.is_valid(po_id):
        po = db["po"].find_one({"_id": ObjectId(po_id)})
    if not po:
        po = db["po"].find_one({"_id": po_id})
    if not po:
        raise HTTPException(status_code=404, detail="PO not found")
    status = payload.decision
    if status not in ["verified", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid decision")
    db["po"].update_one(
        {"_id": po.get("_id")},
        {"$set": {"status": status, "verifier_id": current.get("id"), "verifier_notes": payload.notes}},
    )

    rid = po.get("requirement_id")
    # rid may be ObjectId or string
    rid_filter = {"_id": ObjectId(rid)} if ObjectId.is_valid(rid) else {"_id": rid}
    db["requirement"].update_one(rid_filter, {"$set": {"status": status}})

    req = db["requirement"].find_one(rid_filter)
    if req:
        client = db["user"].find_one({"_id": req.get("client_id")}) or (
            db["user"].find_one({"_id": ObjectId(req.get("client_id"))}) if ObjectId.is_valid(req.get("client_id", "")) else None
        )
        ae = db["user"].find_one({"_id": req.get("ae_id")}) or (
            db["user"].find_one({"_id": ObjectId(req.get("ae_id"))}) if ObjectId.is_valid(req.get("ae_id", "")) else None
        )
        for u in filter(None, [client, ae]):
            notify_email(u.get("email", ""), f"PO {status}", f"PO for requirement {str(req.get("_id"))} has been {status}.")

    add_audit("po", str(po.get("_id")), status, current.get("id"))
    return {"ok": True}


# ----------------------------------------------------------------------------
# AE call completed (log contact)
# ----------------------------------------------------------------------------
@app.post("/requirements/{rid}/call-completed")
def call_completed(rid: str, current=Depends(get_current_user)):
    require_role(current, ["ae", "admin"])
    req = None
    if ObjectId.is_valid(rid):
        req = db["requirement"].find_one({"_id": ObjectId(rid)})
    if not req:
        req = db["requirement"].find_one({"_id": rid})
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")
    uid = current.get("id") or str(current.get("_id"))
    if current.get("role") == "ae" and req.get("ae_id") != uid:
        raise HTTPException(status_code=403, detail="Forbidden")
    add_audit("requirement", str(req.get("_id")), "call_completed", uid)
    return {"ok": True}


# ----------------------------------------------------------------------------
# Audit logs
# ----------------------------------------------------------------------------
@app.get("/audit/{entity}/{entity_id}")
def timeline(entity: str, entity_id: str, current=Depends(get_current_user)):
    logs = list(db["auditlog"].find({"entity": entity, "entity_id": entity_id}).sort("timestamp", 1))
    for l in logs:
        l["id"] = str(l.get("_id"))
    return logs
