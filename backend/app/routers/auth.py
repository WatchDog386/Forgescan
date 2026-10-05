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
    code: str | None = Field(default=None, pattern=r"^\d{6}$", description="Six-digit code from the authenticator app, once one is set up")


class SetupIn(BaseModel):
    setup_token: str = Field(max_length=1000)
    code: str = Field(pattern=r"^\d{6}$")


def _issue(response: Response, user: User) -> dict:
    settings = get_settings()
    response.set_cookie(REFRESH_COOKIE, security.create_token(user, "refresh", settings.session_minutes), httponly=True,
                        samesite="strict", secure=settings.env == "production", max_age=settings.session_minutes * 60, path="/api/v1/auth")
    return {"access_token": security.create_token(user, "access", settings.access_token_minutes), "token_type": "bearer",
            "name": user.name, "role": user.role, "otp_enabled": bool(user.totp_secret)}


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
    password_ok = security.verify_password(user.password_hash, body.password)
    if password_ok and user.totp_secret and body.code is None:
        # The password is right; ask for the authenticator code as a second step. This is not a failed attempt.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, {"message": "Enter the 6-digit code from your authenticator app.", "otp_required": True})
    # Accounts without an authenticator app sign in with the password alone until they set one up.
    good = password_ok and (not user.totp_secret or security.verify_totp(user.totp_secret, body.code))
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


@router.post("/otp/setup")
def otp_setup(user: User = Depends(security.current_user)):
    """Start two-step sign-in: a new secret for the authenticator app, held in a sealed token until it is confirmed."""
    if user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-step sign-in is already set up for this account.")
    secret, _ = security.new_totp_secret()
    return {"secret": secret, "uri": security.totp_uri(secret, user.email), "setup_token": security.seal_totp_setup(user, secret),
            "expires_minutes": security.TOTP_SETUP_MINUTES}


@router.post("/otp/confirm")
def otp_confirm(body: SetupIn, db: Session = Depends(get_db), user: User = Depends(security.current_user)):
    """Switch two-step sign-in on once the app shows a correct code; from then on every sign-in needs one."""
    if user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-step sign-in is already set up for this account.")
    secret = security.open_totp_setup(user, body.setup_token)
    if secret is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This setup has expired. Start again.")
    if not security.code_matches(secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not correct. Check that your phone's clock is set automatically and enter the newest code.")
    user.totp_secret = security.encrypt_totp_secret(secret)
    audit.record(db, "otp.enabled", user.user_id)
    db.commit()
    return {"otp_enabled": True}
