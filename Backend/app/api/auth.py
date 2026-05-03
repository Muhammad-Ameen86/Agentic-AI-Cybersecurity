"""
=============================================================
  THE SENTINEL — Authentication Router
  Stores user accounts in MongoDB: The_Sentinel.users
  
  Endpoints:
    POST /auth/register  — create new account
    POST /auth/login     — authenticate and return session
    GET  /auth/users     — list all registered users (admin)
=============================================================
"""

import hashlib
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, EmailStr

logger = logging.getLogger("sentinel.auth")
router = APIRouter()


# ── Schemas ───────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: str
    password: str
    username: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    email: str
    current_password: str
    new_password: str


class UpdateProfileRequest(BaseModel):
    email: str
    new_username: str


# ── Helpers ───────────────────────────────────────────────
def _hash_password(pw: str) -> str:
    """Simple SHA-256 hash. For production use bcrypt."""
    return hashlib.sha256(pw.encode()).hexdigest()


def _get_users_collection(request: Request):
    """Get the users collection from MongoDB via LTM connection."""
    ltm = getattr(request.app.state, "long_term_memory", None)
    if ltm is None or not ltm.is_connected:
        return None
    return ltm.db["users"]


# ── Register ──────────────────────────────────────────────
@router.post("/register")
async def register(payload: RegisterRequest, request: Request):
    """
    Creates a new user account in MongoDB The_Sentinel.users.
    Stores: email, username, hashed_password, created_at, last_login.
    """
    col = _get_users_collection(request)

    if col is None:
        # MongoDB offline — still allow registration in demo mode
        logger.warning("[Auth] MongoDB offline — returning demo token")
        return {
            "status": "registered",
            "email":  payload.email,
            "username": payload.username or payload.email.split("@")[0],
            "token": "demo-token",
            "mode": "demo",
        }

    # Check if email already exists
    existing = col.find_one({"email": payload.email.lower().strip()})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    username = payload.username.strip() or payload.email.split("@")[0]
    now = datetime.now(timezone.utc)

    user = {
        "email":           payload.email.lower().strip(),
        "username":        username,
        "password_hash":   _hash_password(payload.password),
        "created_at":      now,
        "last_login":      now,
        "login_count":     0,
        "role":            "analyst",
    }

    col.insert_one(user)

    logger.info(f"[Auth] New user registered: {payload.email}")

    return {
        "status":   "registered",
        "email":    payload.email.lower().strip(),
        "username": username,
        "token":    "sentinel-" + _hash_password(payload.email + str(now))[:16],
    }


# ── Login ─────────────────────────────────────────────────
@router.post("/login")
async def login(payload: LoginRequest, request: Request):
    """
    Authenticates user against MongoDB.
    Updates last_login timestamp on success.
    Returns session token + user info.
    """
    col = _get_users_collection(request)

    if col is None:
        # MongoDB offline — demo mode
        logger.warning("[Auth] MongoDB offline — demo login")
        return {
            "status":   "authenticated",
            "email":    payload.email,
            "username": payload.email.split("@")[0],
            "token":    "demo-token",
            "mode":     "demo",
        }

    email = payload.email.lower().strip()
    user  = col.find_one({"email": email})

    if not user:
        logger.warning(f"[Auth] Login failed — user not found: {email}")
        raise HTTPException(status_code=404, detail="Account not found")

    if user["password_hash"] != _hash_password(payload.password):
        logger.warning(f"[Auth] Login failed — wrong password: {email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Update last_login
    now = datetime.now(timezone.utc)
    col.update_one(
        {"email": email},
        {"$set": {"last_login": now}, "$inc": {"login_count": 1}}
    )

    token = "sentinel-" + _hash_password(email + str(now))[:16]

    logger.info(f"[Auth] Login success: {email}")

    return {
        "status":      "authenticated",
        "email":       email,
        "username":    user.get("username", email.split("@")[0]),
        "role":        user.get("role", "analyst"),
        "token":       token,
        "login_count": user.get("login_count", 0) + 1,
    }


# ── Change Password ───────────────────────────────────────
@router.post("/change-password")
async def change_password(payload: ChangePasswordRequest, request: Request):
    col = _get_users_collection(request)
    
    if col is None:
        logger.warning("[Auth] MongoDB offline — returning demo success for password change")
        return {"status": "success", "message": "Demo mode: password changed"}
        
    email = payload.email.lower().strip()
    user = col.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
        
    if user["password_hash"] != _hash_password(payload.current_password):
        raise HTTPException(status_code=401, detail="Invalid current password")
        
    # Update to new password
    new_hash = _hash_password(payload.new_password)
    col.update_one(
        {"email": email},
        {"$set": {"password_hash": new_hash}}
    )
    
    logger.info(f"[Auth] Password successfully changed for: {email}")
    return {"status": "success", "message": "Password updated successfully"}


# ── Update Profile ────────────────────────────────────────
@router.post("/update-profile")
async def update_profile(payload: UpdateProfileRequest, request: Request):
    col = _get_users_collection(request)
    
    if col is None:
        logger.warning("[Auth] MongoDB offline — returning demo success for profile update")
        return {"status": "success", "message": "Demo mode: profile updated"}
        
    email = payload.email.lower().strip()
    new_username = payload.new_username.strip()
    
    # Update or insert the user profile (upsert ensures it saves even if auth wasn't properly initialized)
    col.update_one(
        {"email": email},
        {"$set": {"username": new_username}},
        upsert=True
    )
    
    logger.info(f"[Auth] Profile username successfully updated for: {email} to {new_username}")
    return {"status": "success", "message": "Profile updated successfully"}


# ── List users (admin) ────────────────────────────────────
@router.get("/users")
async def list_users(request: Request):
    """Returns all registered users (excluding password hashes)."""
    col = _get_users_collection(request)
    if col is None:
        return {"users": [], "mode": "demo"}

    users = list(col.find({}, {
        "_id": 0,
        "password_hash": 0,
    }))

    # Convert datetime to string for JSON
    for u in users:
        for k in ["created_at", "last_login"]:
            if k in u and hasattr(u[k], "isoformat"):
                u[k] = u[k].isoformat()

    return {
        "total": len(users),
        "users": users,
    }