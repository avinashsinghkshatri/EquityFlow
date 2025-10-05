"""
EquityFlow - All-in-One FastAPI app (single large file by design for Cursor):
- Config & app init
- Database models (SQLAlchemy)
- Schemas (Pydantic)
- Security (JWT + password hashing)
- Services (Auth, Company, Cap Table, Documents, Signature/Vault, Reporting)
- Routers (endpoints)
- Error handling, logging, transactions
- Minimal templating for documents and dummy PDF stamping

This version:
- Uses passlib's bcrypt_sha256 so passwords >72 bytes are safe
- Adds input validation for name/password with friendly 400 errors
- Fixes Pydantic forward-ref error by defining CapTableSnapshot before use and removing duplicates
"""

from __future__ import annotations

import os
import uuid
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Literal, Annotated, Dict

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, field_validator
from pydantic_settings import BaseSettings
from jose import jwt, JWTError
from passlib.context import CryptContext

from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, ForeignKey,
    Float, Text, UUID as SAUUID
)
    # note: no Enum used
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

from jinja2 import Template
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import LETTER

# ---------------------------------------
# Settings
# ---------------------------------------
class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+psycopg2://equityflow:equityflow_pass@db:5432/equityflow"
    JWT_SECRET: str = "CHANGE_ME"
    JWT_ALG: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DEFAULT_COMPANY_COUNTRY: str = "US"
    VAULT_PATH: str = "/app/app/_vault"

settings = Settings(_env_file=os.path.join(os.path.dirname(__file__), ".env"), _env_file_encoding="utf-8")

# ---------------------------------------
# Logging
# ---------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("equityflow")

# ---------------------------------------
# App init + CORS
# ---------------------------------------
api = FastAPI(title="EquityFlow API", version="1.0.2")
api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------
# Database
# ---------------------------------------
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)

class Base(DeclarativeBase): ...
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------------------
# Security helpers
# ---------------------------------------
# Use bcrypt_sha256 to safely handle passwords longer than bcrypt's 72-byte limit.
pwd_context = CryptContext(
    schemes=["bcrypt_sha256", "bcrypt"],  # keeps compatibility if any legacy hashes exist
    deprecated="auto"
)

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, hp: str) -> bool:
    return pwd_context.verify(p, hp)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALG)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        return payload
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from e

# ---------------------------------------
# RBAC
# ---------------------------------------
Role = Literal["founder", "investor", "employee"]
SecurityType = Literal["SAFE", "CONVERTIBLE_NOTE", "COMMON_STOCK", "PREFERRED_STOCK", "ESOP"]

# ---------------------------------------
# Models
# ---------------------------------------
class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(SAUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    memberships: Mapped[List["Membership"]] = relationship("Membership", back_populates="user")
    signatures: Mapped[List["Signature"]] = relationship("Signature", back_populates="signer")

class Company(Base):
    __tablename__ = "companies"
    id: Mapped[uuid.UUID] = mapped_column(SAUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    country: Mapped[str] = mapped_column(String(10), default=settings.DEFAULT_COMPANY_COUNTRY)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    memberships: Mapped[List["Membership"]] = relationship("Membership", back_populates="company")
    securities: Mapped[List["Security"]] = relationship("Security", back_populates="company")
    documents: Mapped[List["Document"]] = relationship("Document", back_populates="company")

class Membership(Base):
    __tablename__ = "memberships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id"))
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship("User", back_populates="memberships")
    company: Mapped["Company"] = relationship("Company", back_populates="memberships")

class Security(Base):
    __tablename__ = "securities"
    id: Mapped[uuid.UUID] = mapped_column(SAUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id"))
    type: Mapped[str] = mapped_column(String(30))
    holder_email: Mapped[str] = mapped_column(String(255))
    quantity: Mapped[float] = mapped_column(Float, default=0.0)
    price: Mapped[float] = mapped_column(Float, default=0.0)
    terms_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    company: Mapped["Company"] = relationship("Company", back_populates="securities")

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[uuid.UUID] = mapped_column(SAUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id"))
    title: Mapped[str] = mapped_column(String(255))
    template_type: Mapped[str] = mapped_column(String(50))
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    finalized_pdf_path: Mapped[Optional[str]] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    company: Mapped["Company"] = relationship("Company", back_populates="documents")

class Signature(Base):
    __tablename__ = "signatures"
    id: Mapped[uuid.UUID] = mapped_column(SAUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id"))
    signer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    signer_email: Mapped[str] = mapped_column(String(255))
    intent_hash: Mapped[str] = mapped_column(String(128))
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
    user_agent: Mapped[Optional[str]] = mapped_column(String(256))
    signed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    signer: Mapped["User"] = relationship("User", back_populates="signatures")

# ---------------------------------------
# DB bootstrap
# ---------------------------------------
def init_db():
    Base.metadata.create_all(bind=engine)
    os.makedirs(settings.VAULT_PATH, exist_ok=True)

init_db()

# ---------------------------------------
# Schemas (API)
# ---------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str

    @field_validator("name")
    @classmethod
    def trim_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name required")
        return v

    @field_validator("password")
    @classmethod
    def password_len(cls, v: str) -> str:
        if len(v) > 1024:
            raise ValueError("Password too long")
        return v

class UserOut(BaseModel):
    id: uuid.UUID
    email: EmailStr
    name: str
    class Config:
        from_attributes = True

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class CompanyCreate(BaseModel):
    name: str
    country: str | None = None

class CompanyOut(BaseModel):
    id: uuid.UUID
    name: str
    country: str
    class Config:
        from_attributes = True

class MembershipOut(BaseModel):
    id: int
    role: str
    company: CompanyOut
    class Config:
        from_attributes = True

class SecurityCreate(BaseModel):
    type: SecurityType
    holder_email: EmailStr
    quantity: float
    price: float = 0.0
    terms_json: Optional[dict] = None

class SecurityOut(BaseModel):
    id: uuid.UUID
    type: str
    holder_email: EmailStr
    quantity: float
    price: float
    terms_json: str
    created_at: datetime
    class Config:
        from_attributes = True

class DocumentCreate(BaseModel):
    title: str
    template_type: str
    payload: dict

class DocumentOut(BaseModel):
    id: uuid.UUID
    title: str
    template_type: str
    payload_json: str
    finalized_pdf_path: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True

# ---- Cap Table DTOs must be defined BEFORE they are referenced anywhere ----
class CapTableEntry(BaseModel):
    holder_email: EmailStr
    security_type: str
    quantity: float
    value: float

class CapTableSnapshot(BaseModel):
    company_id: uuid.UUID
    total_shares: float
    entries: List[CapTableEntry]

# ---------------------------------------
# Auth dependencies
# ---------------------------------------
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)) -> User:
    payload = decode_token(token)
    uid = payload.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user: User | None = db.get(User, uuid.UUID(uid))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def require_role(company_id: uuid.UUID, user: User, db: Session, allowed: List[Role]):
    membership = db.query(Membership).filter(
        Membership.company_id == company_id, Membership.user_id == user.id
    ).first()
    if not membership or membership.role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

# ---------------------------------------
# Error handlers
# ---------------------------------------
@api.exception_handler(Exception)
async def unhandled_exc(request, exc: Exception):
    logger.exception("Unhandled error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# ---------------------------------------
# Auth routes
# ---------------------------------------
@api.post("/auth/register", response_model=UserOut)
def register_user(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    try:
        phash = hash_password(payload.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    user = User(email=payload.email, name=payload.name, password_hash=phash)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@api.post("/auth/login", response_model=Token)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user.id)})
    return Token(access_token=token)

# ---------------------------------------
# Company & Membership
# ---------------------------------------
@api.post("/companies", response_model=CompanyOut)
def create_company(payload: CompanyCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    company = Company(name=payload.name, country=payload.country or settings.DEFAULT_COMPANY_COUNTRY)
    db.add(company)
    db.flush()
    db.add(Membership(user_id=user.id, company_id=company.id, role="founder"))
    db.commit()
    db.refresh(company)
    return company

@api.get("/me/memberships", response_model=List[MembershipOut])
def my_memberships(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Membership).filter(Membership.user_id == user.id).all()
    return rows

@api.post("/companies/{company_id}/invite", status_code=204)
def invite_member(
    company_id: uuid.UUID,
    email: EmailStr = Body(...),
    role: Role = Body(...),
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    require_role(company_id, user, db, allowed=["founder"])
    existing = db.query(User).filter(User.email == email).first()
    if not existing:
        placeholder = User(email=email, name=email.split("@")[0], password_hash=hash_password(uuid.uuid4().hex))
        db.add(placeholder)
        db.flush()
        uid = placeholder.id
    else:
        uid = existing.id
    if db.query(Membership).filter(Membership.user_id==uid, Membership.company_id==company_id).first():
        raise HTTPException(status_code=400, detail="Already a member")
    db.add(Membership(user_id=uid, company_id=company_id, role=role))
    db.commit()
    return JSONResponse(status_code=204, content=None)

# ---------------------------------------
# Securities (issuance)
# ---------------------------------------
@api.post("/companies/{company_id}/securities", response_model=SecurityOut)
def issue_security(
    company_id: uuid.UUID,
    payload: SecurityCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_role(company_id, user, db, allowed=["founder"])
    sec = Security(
        company_id=company_id,
        type=payload.type,
        holder_email=str(payload.holder_email),
        quantity=payload.quantity,
        price=payload.price,
        terms_json=(payload.terms_json or {}).__str__(),
    )
    db.add(sec)
    db.commit()
    db.refresh(sec)
    return sec

@api.get("/companies/{company_id}/securities", response_model=List[SecurityOut])
def list_securities(company_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    require_role(company_id, user, db, allowed=["founder", "investor", "employee"])
    return db.query(Security).filter(Security.company_id == company_id).order_by(Security.created_at.desc()).all()

# ---------------------------------------
# Cap Table
# ---------------------------------------
def compute_captable(db: Session, company_id: uuid.UUID) -> CapTableSnapshot:
    rows = db.query(Security).filter(Security.company_id == company_id).all()
    total = sum([r.quantity for r in rows if r.type in ("COMMON_STOCK", "PREFERRED_STOCK", "ESOP")])
    entries: List[CapTableEntry] = []
    for r in rows:
        val = r.quantity * (r.price or 0.0)
        entries.append(CapTableEntry(holder_email=r.holder_email, security_type=r.type, quantity=r.quantity, value=val))
    return CapTableSnapshot(company_id=company_id, total_shares=total, entries=entries)

@api.get("/companies/{company_id}/captable", response_model=CapTableSnapshot)
def captable(company_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    require_role(company_id, user, db, allowed=["founder", "investor", "employee"])
    return compute_captable(db, company_id)

# ---------------------------------------
# Documents & templating
# ---------------------------------------
SAFE_TEMPLATE = Template("""
SAFE Agreement
Company: {{ company_name }}
Investor: {{ investor_email }}
Amount: ${{ amount }}
Valuation Cap: ${{ valuation_cap }}
Discount: {{ discount }}%
Date: {{ date }}
""".strip())

NOTE_TEMPLATE = Template("""
Convertible Note
Company: {{ company_name }}
Investor: {{ investor_email }}
Principal: ${{ principal }}
Interest: {{ interest }}%
Maturity: {{ maturity }}
Date: {{ date }}
""".strip())

GRANT_TEMPLATE = Template("""
Stock Option Grant
Company: {{ company_name }}
Employee: {{ employee_email }}
Options: {{ options }}
Vesting: {{ vesting }}
Cliff: {{ cliff }}
Date: {{ date }}
""".strip())

def render_document(template_type: str, payload: dict) -> str:
    now = datetime.utcnow().date().isoformat()
    if template_type.upper() == "SAFE":
        return SAFE_TEMPLATE.render(date=now, **payload)
    if template_type.upper() == "CONVERTIBLE_NOTE":
        return NOTE_TEMPLATE.render(date=now, **payload)
    if template_type.upper() == "GRANT":
        return GRANT_TEMPLATE.render(date=now, **payload)
    return Template("Generic Document\n\n{{ body }}\nDate: {{ date }}").render(date=now, **payload)

@api.post("/companies/{company_id}/documents", response_model=DocumentOut)
def create_document(
    company_id: uuid.UUID,
    payload: DocumentCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_role(company_id, user, db, allowed=["founder"])
    doc = Document(
        company_id=company_id,
        title=payload.title,
        template_type=payload.template_type,
        payload_json=str(payload.payload),
        created_by=user.id,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return doc

@api.get("/companies/{company_id}/documents", response_model=List[DocumentOut])
def list_documents(company_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    require_role(company_id, user, db, allowed=["founder", "investor", "employee"])
    return db.query(Document).filter(Document.company_id == company_id).order_by(Document.created_at.desc()).all()

@api.get("/documents/{document_id}/preview.txt")
def preview_document(document_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    company = db.get(Company, doc.company_id)
    text = render_document(doc.template_type, eval(doc.payload_json) | {"company_name": company.name})
    return JSONResponse({"title": doc.title, "template_type": doc.template_type, "text": text})

# ---------------------------------------
# Digital signature flow
# ---------------------------------------
def stamp_pdf_to_vault(title: str, body_text: str, sign_meta: Dict[str, str]) -> str:
    filename = f"{uuid.uuid4()}_{title.replace(' ', '_')}.pdf"
    path = os.path.join(settings.VAULT_PATH, filename)
    c = canvas.Canvas(path, pagesize=LETTER)
    width, height = LETTER
    y = height - 72
    for line in body_text.split("\n"):
        c.drawString(72, y, line[:1000])
        y -= 14
        if y < 72:
            c.showPage()
            y = height - 72
    c.showPage()
    y = height - 100
    c.drawString(72, y, "=== Signature ===")
    y -= 16
    for k, v in sign_meta.items():
        c.drawString(72, y, f"{k}: {v}")
        y -= 14
    c.save()
    return path

class SignIntentIn(BaseModel):
    document_id: uuid.UUID
    signer_email: EmailStr

class SignConfirmIn(BaseModel):
    document_id: uuid.UUID
    signer_email: EmailStr
    intent_hash: str

@api.post("/sign/intent")
def sign_intent(payload: SignIntentIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, payload.document_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    company = db.get(Company, doc.company_id)
    doc_text = render_document(doc.template_type, eval(doc.payload_json) | {"company_name": company.name})
    h = hashlib.sha256()
    h.update(doc_text.encode("utf-8"))
    h.update(str(payload.signer_email).encode("utf-8"))
    h.update(str(doc.id).encode("utf-8"))
    intent_hash = h.hexdigest()
    return {"intent_hash": intent_hash, "document_preview": doc_text[:2000]}

@api.post("/sign/confirm")
def sign_confirm(payload: SignConfirmIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, payload.document_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    sig = Signature(
        document_id=doc.id,
        signer_id=user.id,
        signer_email=str(payload.signer_email),
        intent_hash=payload.intent_hash,
        ip_address="0.0.0.0",
        user_agent="api-client",
        signed_at=datetime.utcnow(),
    )
    db.add(sig)
    db.flush()

    company = db.get(Company, doc.company_id)
    doc_text = render_document(doc.template_type, eval(doc.payload_json) | {"company_name": company.name})
    pdf_path = stamp_pdf_to_vault(
        title=doc.title,
        body_text=doc_text,
        sign_meta={
            "Signer": str(payload.signer_email),
            "Signer User ID": str(user.id),
            "Intent Hash (sha256)": payload.intent_hash,
            "Signed At (UTC)": datetime.utcnow().isoformat(),
            "Document ID": str(doc.id)
        }
    )
    doc.finalized_pdf_path = pdf_path
    db.commit()
    db.refresh(doc)
    return {"status": "signed", "document_id": str(doc.id), "vault_pdf": pdf_path}

# ---------------------------------------
# Employee ESOP portal
# ---------------------------------------
@api.get("/employee/portfolio")
def employee_portfolio(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Security).filter(Security.holder_email == user.email).all()
    grouped: Dict[str, List[Security]] = {}
    for r in rows:
        grouped.setdefault(str(r.company_id), []).append(r)
    return grouped

# ---------------------------------------
# Reporting & Data Room
# ---------------------------------------
class ReportRequest(BaseModel):
    company_id: uuid.UUID
    report_type: Literal["ownership", "dataroom"]

@api.post("/reports/generate")
def generate_report(req: ReportRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    require_role(req.company_id, user, db, allowed=["founder"])
    if req.report_type == "ownership":
        snap = compute_captable(db, req.company_id)
        return {"type": "ownership", "data": snap.dict()}
    elif req.report_type == "dataroom":
        docs = db.query(Document).filter(Document.company_id == req.company_id).all()
        secs = db.query(Security).filter(Security.company_id == req.company_id).all()
        return {
            "type": "dataroom",
            "documents": [d.title for d in docs],
            "securities_count": len(secs),
            "timestamp": datetime.utcnow().isoformat()
        }
    else:
        raise HTTPException(400, "Unknown report type")

# ---------------------------------------
# Health
# ---------------------------------------
@api.get("/healthz")
def healthz():
    return {"status": "ok"}
