"""
Database Schemas for SaaSOTY v1

Each Pydantic model represents a MongoDB collection.
Collection name is the lowercase class name (e.g., User -> "user").
"""
from typing import Optional, Literal, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


Role = Literal["client", "ae", "verifier", "admin"]


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Hashed password")
    role: Role = Field("client", description="User role")
    assigned_ae_id: Optional[str] = Field(None, description="AE assigned to this client")
    email_verified: bool = Field(False, description="Email verified flag")
    verification_token: Optional[str] = Field(None, description="Email verification token")
    reset_token: Optional[str] = Field(None, description="Password reset token")


RequirementType = Literal["hardware", "software"]
SoftwareSubType = Literal["new", "renewal", "upgrade"]
RequirementStatus = Literal[
    "draft",
    "pending_ae_estimate",
    "estimate_sent",
    "awaiting_client_decision",
    "client_requested_call",
    "client_good_to_go",
    "po_submitted",
    "pending_verification",
    "verified",
    "rejected",
]


class Requirement(BaseModel):
    client_id: str = Field(...)
    ae_id: Optional[str] = Field(None)
    type: RequirementType
    subtype: Optional[SoftwareSubType] = None
    status: RequirementStatus = "pending_ae_estimate"
    details: Dict[str, Any] = Field(..., description="Flexible details payload")
    attachments: List[Dict[str, Any]] = Field(default_factory=list)


class Estimate(BaseModel):
    requirement_id: str
    ae_id: str
    amount: float
    currency: str = "USD"
    breakdown: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None
    status: Literal["draft", "sent"] = "draft"


class PO(BaseModel):
    requirement_id: str
    po_number: str
    file_url: Optional[str] = None
    remarks: Optional[str] = None
    verifier_id: Optional[str] = None
    status: Literal["pending_verification", "verified", "rejected"] = "pending_verification"
    verifier_notes: Optional[str] = None


class AuditLog(BaseModel):
    entity: Literal["requirement", "estimate", "po", "user"]
    entity_id: str
    action: str
    actor_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    meta: Dict[str, Any] = Field(default_factory=dict)
