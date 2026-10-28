"""Auth JWT + rôles (admin/analyst/viewer)."""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext

from app.core.config import settings
from app.services import store

pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer = HTTPBearer()

ALGO = "HS256"


def create_token(user_id: str, org_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "org": org_id,
        "role": role,
        "exp": datetime.now(timezone.utc)
        + timedelta(minutes=settings.token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGO)


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        payload = jwt.decode(creds.credentials, settings.secret_key, algorithms=[ALGO])
    except JWTError:
        raise HTTPException(401, "Token invalide ou expiré")
    user = store.get("users", payload["sub"])
    if not user:
        raise HTTPException(401, "Utilisateur inconnu")
    return {**user, "org_id": payload["org"], "role": payload["role"]}


def require_role(*roles: str):
    def checker(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, f"Rôle requis : {roles}")
        return user
    return checker


def hash_password(p: str) -> str:
    return pwd.hash(p)


def verify_password(p: str, hashed: str) -> bool:
    return pwd.verify(p, hashed)
