from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .. import audit, security
from ..config import get_settings
from ..database import get_db
from ..limits import limiter
from ..models import User, utcnow

router = APIRouter(prefix="/auth", tags=["auth"])
REFRESH_COOKIE = "ainidr_refresh"


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=200)
    code: str = Field(pattern=r"^\d{6}$", description="Six-digit code from the authenticator app")


def _issue(response: Response, user: User) -> dict:
    settings = get_settings()
    response.set_cookie(REFRESH_COOKIE, security.create_token(user, "refresh", settings.session_minutes), httponly=True,
                        samesite="strict", secure=settings.env == "production", max_age=settings.session_minutes * 60, path="/api/v1/auth")
    return {"access_token": security.create_token(user, "access", settings.access_token_minutes), "token_type": "bearer",
            "name": user.name, "role": user.role}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    limiter.check(f"login:{request.client.host if request.client else 'unknown'}", 20)
    user = db.query(User).filter(User.email == body.email.lower()).first()
    refused = HTTPException(status.HTTP_401_UNAUTHORIZED, "The email, password or code is not correct.")  # the same for every failure
    if user is None or user.status != "active":
        audit.record(db, "login.failed", detail="unknown or inactive account")
        db.commit()
        raise refused
    if user.locked_until and user.locked_until > utcnow():
        audit.record(db, "login.refused", user.user_id, detail="account locked")
        db.commit()
        raise HTTPException(status.HTTP_423_LOCKED, "This account is locked after too many attempts. Try again in 15 minutes.")
    good = security.verify_password(user.password_hash, body.password) and bool(user.totp_secret) and security.verify_totp(user.totp_secret, body.code)
    if not good:
        user.failed_logins += 1
        if user.failed_logins >= security.MAX_FAILED_LOGINS:  # FR-05
            user.locked_until, user.failed_logins = utcnow() + security.LOCKOUT, 0
        audit.record(db, "login.failed", user.user_id)
        db.commit()
        raise refused
    user.failed_logins, user.locked_until = 0, None
    audit.record(db, "login.success", user.user_id)
    db.commit()
    return _issue(response, user)


@router.post("/refresh")
def refresh(response: Response, token: str | None = Cookie(default=None, alias=REFRESH_COOKIE), db: Session = Depends(get_db)):
    """Give a new access token while the session is still active (FR-06: it ends after 30 minutes without activity)."""
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in first.")
    return _issue(response, security.user_from_token(db, token, "refresh"))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response):
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
