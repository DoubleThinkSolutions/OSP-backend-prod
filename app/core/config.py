# app/core/config.py
import os
from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Open Source Panopticon Backend"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False # Set to False in production

    # --- Database Configuration ---
    # Loaded from environment (e.g., .env file or injected by orchestration)
    # Example: postgresql+asyncpg://USER:PASSWORD@HOST:PORT/DB_NAME
    DATABASE_URL: str

    # --- API Key for initial device registration or admin purposes (optional) ---
    # This key could be used by a trusted process to register new devices and their API keys.
    # For true production, this itself should be managed securely.
    ADMIN_API_KEY: Optional[str] = None # e.g., "a_very_secret_admin_key_for_setup"

    TEMP_UPLOAD_DIR: str = "/tmp/osp_uploads"

    # --- Object Storage (S3/MinIO compatible) ---
    S3_ENABLED: bool = False
    S3_ENDPOINT_URL: Optional[str] = None
    S3_ACCESS_KEY_ID: Optional[str] = None # Loaded from env/secrets manager
    S3_SECRET_ACCESS_KEY: Optional[str] = None # Loaded from env/secrets manager
    S3_BUCKET_NAME: Optional[str] = "osp-evidence-bucket"
    S3_REGION_NAME: Optional[str] = None
    S3_USE_SSL: bool = True

    # --- Celery Configuration ---
    CELERY_ENABLED: bool = False
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    CELERY_TASK_DEFAULT_QUEUE: str = "osp_default_queue"
    # CELERY_TASK_ROUTES: Optional[dict] = { ... } # Example from before

    # --- Security Settings ---
    # For hashing API keys. Generate a strong, unique salt per deployment.
    # Store this in your environment secrets, NOT hardcoded.
    API_KEY_PEPPER: str = "default_pepper_please_change_in_production_env" # LOAD FROM ENV!
    # Example for .env: API_KEY_PEPPER="a_very_long_and_random_pepper_string"

    # --- Security Settings ---
    API_KEY_PEPPER: str = "default_pepper_please_change_in_production_env"

    # --- JWT Token Settings (for User Authentication) ---
    # Generate these with: openssl rand -hex 32
    JWT_SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7" # LOAD FROM ENV!
    JWT_ALGORITHM: str = "HS256"
    # Token expiry in minutes
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # e.g., 1 day
    # JWT_REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7 # e.g., 7 days (for refresh tokens, future)

    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = 'utf-8'

    def is_s3_configured(self) -> bool:
        # ... (same as before) ...
        if not self.S3_ENABLED: return False
        return all([self.S3_ENDPOINT_URL, self.S3_ACCESS_KEY_ID, self.S3_SECRET_ACCESS_KEY, self.S3_BUCKET_NAME])


settings = Settings()

if settings.JWT_SECRET_KEY == "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7":
    print("CRITICAL WARNING: JWT_SECRET_KEY is using the default example value. "
          "This is insecure for production. Please set a strong, unique JWT_SECRET_KEY in your environment.")

if not settings.API_KEY_PEPPER or settings.API_KEY_PEPPER == "default_pepper_please_change_in_production_env":
    print("CRITICAL WARNING: API_KEY_PEPPER is not set or is using the default value. "
          "This is insecure for production. Please set a strong, unique pepper in your environment.")

settings = Settings()

if settings.S3_ENABLED and not settings.is_s3_configured():
    # Raise an error or log a prominent warning if S3 is enabled but not fully configured
    # For now, let's print a warning. In production, this might be a startup error.
    print("WARNING: S3_ENABLED is True, but S3 configuration is incomplete in .env. "
          "S3 operations may fail. Please check S3_ENDPOINT_URL, S3_ACCESS_KEY_ID, "
          "S3_SECRET_ACCESS_KEY, and S3_BUCKET_NAME.")

# Ensure temp upload directory exists (might still be used for initial buffering)
if not os.path.exists(settings.TEMP_UPLOAD_DIR):
    os.makedirs(settings.TEMP_UPLOAD_DIR, exist_ok=True)