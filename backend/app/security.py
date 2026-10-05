"""Passwords, one-time codes, tokens and role checks (SDS 6.8)."""
import base64
import hashlib
from datetime import timedelta

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import ROLES, User, utcnow

_hasher = PasswordHasher()  # Argon2id (NFR-07)
_bearer = HTTPBearer(auto_error=False)
MAX_FAILED_LOGINS, LOCKOUT = 5, timedelta(minutes=15)
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def _fernet() -> Fernet:
    key = hashlib.sha256(get_settings().secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def new_totp_secret() -> tuple[str, str]:
    """Return (secret to show the user once, encrypted form to store)."""
    secret = pyotp.random_base32()
    return secret, _fernet().encrypt(secret.encode()).decode()


def verify_totp(encrypted_secret: str, code: str) -> bool:
    secret = _fernet().decrypt(encrypted_secret.encode()).decode()
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="AI-NIDR")


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_token(user: User, kind: str, minutes: int) -> str:
    payload = {"sub": str(user.user_id), "role": user.role, "kind": kind, "exp": utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(payload, get_settings().secret_key, algorithm=ALGORITHM)


def decode_token(token: str, kind: str) -> dict:
    try:
        payload = jwt.decode(token, get_settings().secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The access token is missing, wrong or expired.") from None
    if payload.get("kind") != kind:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The access token is of the wrong kind.")
    return payload


def user_from_token(db: Session, token: str, kind: str = "access") -> User:
    payload = decode_token(token, kind)
    user = db.get(User, int(payload["sub"]))
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This account is not active.")
    return user


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer), db: Session = Depends(get_db)) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in first.")
    return user_from_token(db, credentials.credentials)


def require_role(minimum: str):
    """Allow users whose role is at least `minimum` (FR-03)."""

    def dependency(user: User = Depends(current_user)) -> User:
        if ROLES.index(user.role) < ROLES.index(minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action.")
        return user

    return dependency
