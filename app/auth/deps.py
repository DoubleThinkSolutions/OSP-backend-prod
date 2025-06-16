# app/auth_deps.py
from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer # For OAuth2 password flow
from sqlalchemy.ext.asyncio import AsyncSession
import uuid # Import uuid for converting string ID to UUID

from app.core.config import settings
from app.database import get_db_session
from app import crud, models, schemas, security # models for type hint, security for decode

# --- OAuth2 Password Bearer Scheme ---
# This tells FastAPI where to look for the token (Authorization: Bearer <token>)
# tokenUrl should point to your actual token endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/users/token")

async def get_current_user(
    db: AsyncSession = Depends(get_db_session), token: str = Depends(oauth2_scheme)
) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token_data = security.decode_access_token(token)
    if not token_data or not token_data.sub:
        raise credentials_exception
    
    try:
        user_id = uuid.UUID(token_data.sub) # Assuming 'sub' stores the user's UUID as string
    except ValueError:
        raise credentials_exception # Invalid UUID format in token subject

    user = await crud.get_user_by_id(db, user_id=user_id)
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user

# --- Role-Based Access Control (RBAC) Dependency Example ---
# This is a factory for creating role-checking dependencies.
def require_role(required_roles: List[str]):
    async def role_checker(current_user: models.User = Depends(get_current_user)) -> models.User:
        if current_user.role not in required_roles and not current_user.is_superuser:
            # Superusers can bypass role checks if desired, or handle their permissions separately
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User does not have the required role(s): {', '.join(required_roles)}"
            )
        return current_user
    return role_checker

# Specific role dependencies
get_current_active_admin_user = require_role(["admin"])
get_current_active_auditor_user = require_role(["auditor", "admin"]) # Auditor or Admin