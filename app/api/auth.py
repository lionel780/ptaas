from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.auth import (create_token, hash_password, verify_password)
from app.services import store
from app.services.credits_service import ensure_org

router = APIRouter(prefix="/api/auth", tags=["auth"])


class Register(BaseModel):
    email: str
    password: str
    org_name: str
    plan: str = "startup"


class Login(BaseModel):
    email: str
    password: str


@router.post("/register")
def register(body: Register):
    if store.find("users", email=body.email):
        raise HTTPException(409, "Email déjà utilisé")
    org = ensure_org(body.org_name, body.plan)
    user = store.insert("users", {
        "email": body.email, "password_hash": hash_password(body.password),
        "org_id": org["id"], "role": "admin" if not store.find("users") else "analyst",
    })
    return {"token": create_token(user["id"], org["id"], user["role"]),
            "org_id": org["id"], "role": user["role"], "plan": org["plan"]}


@router.post("/login")
def login(body: Login):
    users = store.find("users", email=body.email)
    if not users or not verify_password(body.password, users[0]["password_hash"]):
        raise HTTPException(401, "Identifiants invalides")
    u = users[0]
    return {"token": create_token(u["id"], u["org_id"], u["role"]),
            "org_id": u["org_id"], "role": u["role"]}
