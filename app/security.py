# app/security.py
import hashlib
import secrets
from typing import Tuple, Optional, Any # Added Any
from datetime import datetime, timedelta # Changed import for timedelta

from passlib.context import CryptContext # For password hashing
import jwt # PyJWT library

from app.core.config import settings
from app.schemas import TokenData # Import TokenData schema

# --- API Key Hashing (from Turn 8) ---
PEPPER = settings.API_KEY_PEPPER.encode('utf-8')
API_KEY_PREFIX_LENGTH = 8
def generate_api_key_and_hash() -> Tuple[str, str, str]: # ... (same) ...
    api_key = secrets.token_urlsafe(32); prefix = api_key[:API_KEY_PREFIX_LENGTH]
    salted_key = PEPPER + api_key.encode('utf-8'); hashed_key = hashlib.sha256(salted_key).hexdigest()
    return api_key, prefix, hashed_key
def verify_api_key(api_key_to_check: str, stored_hashed_key: str) -> bool: # ... (same) ...
    salted_key_to_check = PEPPER + api_key_to_check.encode('utf-8'); hashed_key_to_check = hashlib.sha256(salted_key_to_check).hexdigest()
    return secrets.compare_digest(hashed_key_to_check, stored_hashed_key)


# --- Password Hashing (using Passlib) ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# --- JWT Token Utilities ---
ALGORITHM = settings.JWT_ALGORITHM
SECRET_KEY = settings.JWT_SECRET_KEY
ACCESS_TOKEN_EXPIRE_MINUTES = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()}) # Add issued_at time
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[TokenData]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # 'sub' typically holds the username or user ID.
        # We'll store user ID as string in 'sub'.
        username: Optional[str] = payload.get("sub")
        scopes = payload.get("scopes", []) # Get scopes if present
        if username is None:
            return None # Or raise credentials_exception
        return TokenData(sub=username, scopes=scopes)
    except jwt.ExpiredSignatureError:
        # Handle expired token specifically if needed by raising a custom exception
        # or by returning a specific error code/message that FastAPI can interpret.
        # For now, let it propagate as PyJWTError or return None.
        print("Token has expired.")
        return None
    except jwt.PyJWTError as e:
        # Handle other JWT errors (invalid signature, invalid token, etc.)
        print(f"JWT Error: {e}")
        return None