# app/main.py
import json
from fastapi import FastAPI, Depends, HTTPException, Security, UploadFile, File, Form
from fastapi.security.api_key import APIKeyHeader, APIKey
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from fastapi.responses import JSONResponse
import time # For rate limiting and process time header

from app.core.config import settings
from app.database import get_db_session, create_db_and_tables
from app import schemas, models, crud
from app.services.file_service import file_storage_service, initialize_storage_service

from app.core.config import settings

from app.services.file_service import file_storage_service
from app.services.file_service import file_storage_service, initialize_storage_service

from app.celery_app import celery_app # Import our Celery app instance
from app.core.config import settings # Ensure settings is imported

from app import security # Import new security utils
from app.models import Device as DeviceModel # For type hinting in auth
from app.auth_deps import get_current_user, get_current_active_admin_user, authenticate_device_api_key # Import new auth deps

import logging # For standard logging
from app.core.logging_config import setup_logging # Import our logging setup
from prometheus_client import Histogram # For request latency histogram
from starlette.middleware.cors import CORSMiddleware # For CORS

# --- Call logging setup early ---
# This should ideally be one of the first things done.
setup_logging()
logger = logging.getLogger(__name__) # Get a logger for this module

# --- Prometheus Metrics (Simplified for V1) ---
from prometheus_client import Counter, make_asgi_app
manifests_ingested_total = Counter("osp_manifests_ingested_total", "Total number of manifests ingested")
files_uploaded_total = Counter("osp_files_uploaded_total", "Total number of files uploaded (segments)")
# Define error counter with a label
ingestion_errors_total = Counter(
    "osp_ingestion_errors_total", 
    "Total number of ingestion errors",
    ["error_type"] # Add labels you want to use
)

REQUEST_LATENCY = Histogram(
    "osp_api_request_latency_seconds",
    "API Request Latency in seconds",
    ["method", "endpoint"]
)

# --- FastAPI App Initialization ---
app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    debug=settings.DEBUG,
    version="0.4.0-prod-logging-metrics" # Updated version
)

# --- Middleware ---
# CORS Middleware (adjust origins as needed for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else ["https://your-frontend-domain.com"], # Restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Latency tracking middleware (must be before error handling that might return early)
@app.middleware("http")
async def track_request_latency(request: Request, call_next: RequestResponseEndpoint):
    start_time = time.time()
    
    # Attempt to match route to get endpoint template for metrics
    # This part can be tricky and might need a more robust solution for complex routers/apps
    # For now, use a simplified approach.
    endpoint_label = "unknown_endpoint"
    for route in request.app.routes:
        match = route.matches(request.scope)
        if match[0] == 상태.MATCH: # from starlette.routing import Match
            endpoint_label = route.path
            break
            
    response = await call_next(request)
    latency = time.time() - start_time
    REQUEST_LATENCY.labels(method=request.method, endpoint=endpoint_label).observe(latency)
    # Add custom request logging here if Uvicorn/Gunicorn access logs are disabled
    logger.info(
        "Request processed",
        extra={
            "http_method": request.method,
            "http_path": request.url.path,
            "http_status_code": response.status_code,
            "http_latency_seconds": f"{latency:.4f}",
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown")
        }
    )
    return response

# StandardSecurityHeadersMiddleware and RateLimitMiddleware (from Turn 6, ensure they are added AFTER CORS and latency)
# ... app.add_middleware(StandardSecurityHeadersMiddleware) ...
# ... if not settings.DEBUG: app.add_middleware(RateLimitMiddleware) ...
# Order matters: CORS -> Latency -> Security Headers -> Rate Limiting -> (Error Handling Middleware - FastAPI does this)

# --- Security Middleware: Headers & Process Time ---
class StandardSecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY" # Default, adjust if OSP needs framing
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Content-Security-Policy is complex and needs careful thought for a specific frontend
        # response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(StandardSecurityHeadersMiddleware)

# --- Rate Limiting (Simple In-Memory Example) ---
# For production, use Redis with a library like slowapi or a gateway feature
RATE_LIMIT_MAX_REQUESTS = 100  # Max requests
RATE_LIMIT_WINDOW_SECONDS = 60  # Per minute
rate_limit_tracker: Dict[str, List[float]] = {}

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()

        # Clean up old timestamps for this IP
        if client_ip in rate_limit_tracker:
            rate_limit_tracker[client_ip] = [
                t for t in rate_limit_tracker[client_ip] if t > current_time - RATE_LIMIT_WINDOW_SECONDS
            ]
        else:
            rate_limit_tracker[client_ip] = []

        # Check limit
        if len(rate_limit_tracker[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            # You might want to log this event
            ingestion_errors_total.labels(error_type='rate_limit').inc() # Example new label
            return JSONResponse(
                status_code=429, # Too Many Requests
                content={"detail": f"Rate limit exceeded for IP {client_ip}. Try again later."}
            )

        rate_limit_tracker[client_ip].append(current_time)
        response = await call_next(request)
        return response

if not settings.DEBUG: # Apply rate limiting only when not in DEBUG mode, or configure differently
    app.add_middleware(RateLimitMiddleware)


# --- API Key Authentication (Refined slightly for future DB-backed keys) ---
# For now, still checks against settings.DEVICE_API_KEYS
# In future, this could query a DB table of APIKeys associated with Devices.
api_key_header_device = APIKeyHeader(name="X-DEVICE-API-KEY", auto_error=False)

async def verify_device_api_key(
    db: AsyncSession, # Added db session for future use
    api_key_header_value: Optional[str] = Security(api_key_header_device)
) -> str: # Returns the validated key or raises HTTPException
    if not api_key_header_value:
        ingestion_errors_total.labels(error_type='auth_missing_key').inc()
        raise HTTPException(status_code=403, detail="X-DEVICE-API-KEY header missing.")

    # Current: Check against static list in settings
    if api_key_header_value in settings.DEVICE_API_KEYS:
        # TODO Future: When API keys are in DB:
        # hashed_key = hashlib.sha256(api_key_header_value.encode()).hexdigest()
        # db_api_key_entry = await crud.get_api_key_entry(db, hashed_key=hashed_key)
        # if db_api_key_entry and db_api_key_entry.is_active:
        #     await crud.update_api_key_last_used(db, db_api_key_entry.id)
        #     return api_key_header_value # Or return associated device_id / user_id
        # else:
        #     ingestion_errors_total.labels(error_type='auth_invalid_key').inc()
        #     raise HTTPException(status_code=403, detail="Invalid or inactive X-DEVICE-API-KEY.")
        return api_key_header_value # Return the valid key for now
    else:
        ingestion_errors_total.labels(error_type='auth_invalid_key').inc()
        raise HTTPException(status_code=403, detail="Invalid X-DEVICE-API-KEY.")

# Modified dependency for API routes needing API key auth
async def get_validated_api_key(
    db: AsyncSession = Depends(get_db_session), # Inject DB session
    api_key: str = Security(verify_device_api_key) # Use the verifier
) -> str:
    return api_key # The key itself is returned if valid

# --- Event Handlers (e.g., for database initialization) ---
@app.on_event("startup")
async def on_startup():
    logger.info("Starting OSP Backend Service...", extra={"service_version": app.version})
    if settings.DEBUG:
        logger.debug("DEBUG mode: Attempting to create database tables...")
        await create_db_and_tables()
        logger.debug("Database tables check/creation complete.")
    await initialize_storage_service()
    logger.info(f"OSP Backend Service started. Listening on {settings.HOST}:{settings.PORT}")

@app.on_event("shutdown")
async def on_shutdown():
    logger.info("OSP Backend Service shutting down.")

# --- API Endpoints ---
API_ROUTER_V1_PREFIX = settings.API_V1_STR

@app.post(
    f"{settings.API_V1_STR}/ingest/manifest_with_segments", # Use settings.API_V1_STR
    response_model=schemas.ManifestIngestionResponse,
    status_code=201,
    summary="Ingest a manifest describing multiple segments, and upload associated segment files.",
    description="Submit a manifest (as JSON string) detailing multiple video/audio segments. "
                "Simultaneously upload the corresponding segment files as a list of `UploadFile`."
                "The order of files in `segment_files` should match the order of segments in `manifest.segments_data`."
)
async def ingest_manifest_with_segment_files(
    manifest_json_str: str = Form(..., description="Manifest data as a JSON string."),
    segment_files: List[UploadFile] = File(..., description="List of segment files. Order must match segments_data in manifest."),
    db: AsyncSession = Depends(get_db_session),
    authenticated_device: DeviceModel = Depends(authenticate_device_api_key) # Use the new auth dependency
):
    try:
        manifest_data_dict = json.loads(manifest_json_str)
        manifest_create_schema = schemas.ManifestCreate(**manifest_data_dict)
    except json.JSONDecodeError: # ... (error handling) ...
        ingestion_errors_total.labels(error_type='json_decode').inc(); raise HTTPException(status_code=400, detail="Invalid JSON format.")
    except Exception as e: # ... (error handling) ...
        ingestion_errors_total.labels(error_type='validation').inc(); raise HTTPException(status_code=422, detail=f"Manifest validation error: {str(e)}")

    if len(manifest_create_schema.segments_data) != len(segment_files): # ... (error handling) ...
        ingestion_errors_total.labels(error_type='file_segment_mismatch').inc(); raise HTTPException(status_code=400, detail="Mismatch segments and files.")

    # Verify that the device_id_str in the manifest matches the authenticated device
    if manifest_create_schema.device_id_str != authenticated_device.device_id_str:
        ingestion_errors_total.labels(error_type='auth_device_id_mismatch').inc()
        raise HTTPException(
            status_code=403, 
            detail=f"Manifest device_id_str '{manifest_create_schema.device_id_str}' "
                   f"does not match authenticated device '{authenticated_device.device_id_str}'."
        )
    
    # Device is already fetched and authenticated (it's `authenticated_device`)
    db_device = authenticated_device # Use the object returned by authentication
    
    db_manifest = await crud.create_manifest(db, manifest=manifest_create_schema, device_db_id=db_device.id)

    # ... (segment processing loop - same as Turn 6, using db_device.device_id_str and db_manifest.id) ...
    # ... (Celery task dispatch - same as Turn 6) ...
    processed_segment_db_ids = []
    for i, segment_meta_create in enumerate(manifest_create_schema.segments_data):
        upload_file_segment = segment_files[i]
        try:
            storage_key, file_size, server_hash, storage_type = await file_storage_service.save_upload_file(
                upload_file=upload_file_segment, device_id_str=db_device.device_id_str,
                manifest_db_id=db_manifest.id, segment_index=segment_meta_create.segment_index
            )
            files_uploaded_total.inc()
            hash_status = "MATCH_SERVER_CLIENT" if server_hash == segment_meta_create.sha256_hash_client else "MISMATCH_SERVER_CLIENT"
            if hash_status == "MISMATCH_SERVER_CLIENT": print(f"[WARNING] Hash mismatch for segment {i}...")
        
        except HTTPException as http_exc: ingestion_errors_total.labels(error_type='file_processing_http').inc(); raise http_exc
        except Exception as e: ingestion_errors_total.labels(error_type='file_processing_generic').inc(); raise HTTPException(status_code=500, detail=f"File processing error: {str(e)}")

        db_segment = await crud.create_segment(
            db, segment=segment_meta_create, manifest_id=db_manifest.id,
            storage_path_uri=storage_key, storage_type=storage_type, file_size_bytes=file_size
        )
        db_segment.sha256_hash_server = server_hash; db_segment.hash_verified_status = hash_status
        await db.flush([db_segment]); processed_segment_db_ids.append(db_segment.id)

    manifests_ingested_total.inc()
    
    task_id_str = None
    if settings.CELERY_ENABLED:
        try:
            task_submission = celery_app.send_task("app.tasks.process_manifest_verification", args=[str(db_manifest.id)])
            task_id_str = str(task_submission.id); db_manifest.server_verification_status = "QUEUED_FOR_VERIFICATION"
        except Exception as celery_e:
            print(f"[ERROR] Celery dispatch failed for manifest {db_manifest.id}: {celery_e}")
            db_manifest.server_verification_status = "VERIFICATION_DISPATCH_FAILED"
            ingestion_errors_total.labels(error_type='celery_dispatch').inc()
    
    await db.refresh(db_manifest)
    
    response_message = f"Manifest for device '{db_device.device_id_str}' ({len(processed_segment_db_ids)} segments) received." # More informative
    if task_id_str: response_message += f" Verification queued (Task ID: {task_id_str})." # Same
    # ... (rest of response message logic) ...

    return schemas.ManifestIngestionResponse(
        manifest_id=db_manifest.id, message=response_message, received_at_server=db_manifest.received_at_server
    )

@app.get(f"{API_ROUTER_V1_PREFIX}/manifests/{{manifest_id}}", response_model=schemas.ManifestInDB)
async def read_manifest(manifest_id: uuid.UUID, db: AsyncSession = Depends(get_db_session)):
    # Add auth for this if needed (e.g., admin user or owner device)
    db_manifest = await crud.get_manifest(db, manifest_id=manifest_id)
    if db_manifest is None:
        raise HTTPException(status_code=404, detail="Manifest not found")
    return db_manifest

@app.get(f"{API_ROUTER_V1_PREFIX}/manifests", response_model=List[schemas.ManifestInDB])
async def read_manifests(
    skip: int = 0, limit: int = 100,
    filters: schemas.ManifestQueryFilters = Depends(), # Inject query filters
    db: AsyncSession = Depends(get_db_session)
):
    # Add auth for this if needed
    manifests = await crud.get_manifests(db, skip=skip, limit=limit, filters=filters)
    return manifests

# New endpoint to get segments
@app.get(f"{API_ROUTER_V1_PREFIX}/segments", response_model=List[schemas.SegmentInDB])
async def read_segments(
    skip: int = 0, limit: int = 100,
    filters: schemas.SegmentQueryFilters = Depends(), # Inject query filters
    db: AsyncSession = Depends(get_db_session)
):
    # Add auth for this if needed
    segments = await crud.get_segments(db, skip=skip, limit=limit, filters=filters)
    return segments


@app.get(f"{API_ROUTER_V1_PREFIX}/devices/{{device_id_str}}", response_model=schemas.DeviceInDB)
async def read_device_by_str_id(device_id_str: str, db: AsyncSession = Depends(get_db_session)):
    # Add auth
    db_device = await crud.get_device_by_str_id(db, device_id_str=device_id_str)
    if db_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return db_device

# --- API Key Authentication (Using Database) ---
api_key_header_device = APIKeyHeader(name="X-DEVICE-API-KEY", auto_error=False) # auto_error=False to customize response

async def authenticate_device_api_key(
    db: AsyncSession = Depends(get_db_session),
    api_key_value: Optional[str] = Security(api_key_header_device)
) -> DeviceModel: # Return the authenticated Device model instance
    if not api_key_value:
        ingestion_errors_total.labels(error_type='auth_missing_key').inc()
        raise HTTPException(status_code=401, detail="X-DEVICE-API-KEY header missing.")

    key_prefix = api_key_value[:security.API_KEY_PREFIX_LENGTH]
    db_api_key_entry = await crud.get_api_key_by_prefix(db, prefix=key_prefix)

    if not db_api_key_entry:
        ingestion_errors_total.labels(error_type='auth_invalid_key_prefix').inc()
        raise HTTPException(status_code=401, detail="Invalid API Key (prefix not found).")

    if not db_api_key_entry.is_active:
        ingestion_errors_total.labels(error_type='auth_inactive_key').inc()
        raise HTTPException(status_code=401, detail="API Key is inactive.")
        
    if db_api_key_entry.expires_at and db_api_key_entry.expires_at < dt.datetime.utcnow():
        # Optionally deactivate key here: await crud.deactivate_api_key(db, db_api_key_entry.id)
        ingestion_errors_total.labels(error_type='auth_expired_key').inc()
        raise HTTPException(status_code=401, detail="API Key has expired.")

    if not security.verify_api_key(api_key_value, db_api_key_entry.hashed_key):
        ingestion_errors_total.labels(error_type='auth_invalid_key_hash').inc()
        # TODO: Implement lockout logic for repeated failures from an IP or prefix
        raise HTTPException(status_code=401, detail="Invalid API Key (verification failed).")

    # Key is valid, update last used and return the associated device
    if not db_api_key_entry.device: # Should not happen if DB constraints are correct
        ingestion_errors_total.labels(error_type='auth_key_no_device').inc()
        raise HTTPException(status_code=500, detail="API Key is not associated with a device.")
    
    await crud.update_api_key_last_used(db, db_api_key_entry.id)
    db_api_key_entry.device.last_seen_at = dt.datetime.utcnow() # Update device last_seen
    # db.add(db_api_key_entry.device) # Mark device as dirty for last_seen_at update
    # The session commit in get_db_session will handle this.
    
    return db_api_key_entry.device # Return the authenticated device object

# --- Admin API Key Authentication (Example for registration endpoint) ---
admin_api_key_header = APIKeyHeader(name="X-ADMIN-API-KEY", auto_error=False)
async def authenticate_admin_api_key(admin_key_value: Optional[str] = Security(admin_api_key_header)):
    if not settings.ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Admin functionality not configured on server.")
    if admin_key_value == settings.ADMIN_API_KEY:
        return True
    raise HTTPException(status_code=401, detail="Invalid X-ADMIN-API-KEY.")

@app.post(
    f"{API_ROUTER_V1_PREFIX}/devices/register",
    response_model=schemas.DeviceRegistrationResponse,
    status_code=201,
    summary="Register a new device and issue an API key.",
    description="Requires Admin API Key. Registers a new device based on its string ID "
                "and returns the device details along with a new API key. "
                "The returned API key must be stored securely by the client; it will not be shown again."
)
async def register_new_device(
    registration_data: schemas.DeviceRegistrationRequest,
    db: AsyncSession = Depends(get_db_session),
    _is_admin: bool = Depends(authenticate_admin_api_key) # Protect this endpoint
):
    existing_device = await crud.get_device_by_str_id(db, device_id_str=registration_data.device_id_str)
    if existing_device:
        raise HTTPException(
            status_code=409, # Conflict
            detail=f"Device with device_id_str '{registration_data.device_id_str}' already exists."
        )
    
    device_create_schema = schemas.DeviceCreate(
        device_id_str=registration_data.device_id_str,
        description=registration_data.description
    )
    db_device, raw_api_key = await crud.create_device_with_api_key(db, device_create_schema=device_create_schema)
    
    # We need to refresh db_device to get the api_key_entry populated by the relationship
    await db.refresh(db_device, ['api_key_entry'])

    return schemas.DeviceRegistrationResponse(
        id=db_device.id,
        device_id_str=db_device.device_id_str,
        description=db_device.description,
        created_at=db_device.created_at,
        last_seen_at=db_device.last_seen_at,
        is_active=db_device.is_active,
        api_key=raw_api_key, # Return the raw key ONLY this one time
        api_key_prefix=db_device.api_key_entry.prefix if db_device.api_key_entry else "ERROR_NO_KEY_PREFIX"
    )

# --- User and Authentication Endpoints ---
@app.post(f"{API_ROUTER_V1_PREFIX}/users/token", response_model=schemas.Token, tags=["Authentication"])
async def login_for_access_token(
    db: AsyncSession = Depends(get_db_session),
    form_data: OAuth2PasswordRequestForm = Depends() # Standard form for username (email) & password
):
    user = await crud.get_user_by_email(db, email=form_data.username) # form_data.username is the email
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    # Scopes could be dynamic based on user.role or other attributes
    scopes = [f"role:{user.role}"] 
    if user.is_superuser: scopes.append("superuser")

    access_token_expires = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": str(user.id), "scopes": scopes}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post(f"{API_ROUTER_V1_PREFIX}/users/register", response_model=schemas.UserPublic, status_code=201, tags=["Users"])
async def register_user(
    user_in: schemas.UserCreate,
    db: AsyncSession = Depends(get_db_session),
    # _admin_user: models.User = Depends(get_current_active_admin_user) # Example: Protect with admin role
    # For now, let's make registration open for testing, or use ADMIN_API_KEY for first admin
    _is_admin_via_key: bool = Depends(authenticate_admin_api_key) # Or use this if preferred
):
    db_user = await crud.get_user_by_email(db, email=user_in.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    # First user registered could be made an admin/superuser
    # users_count = await db.execute(select(func.count(models.User.id))) # Needs func from sqlalchemy
    # if users_count.scalar_one() == 0:
    #     user_in.role = "admin" 
    #     user_in.is_superuser = True # Manually set for first user
        
    created_user = await crud.create_user(db, user=user_in)
    return created_user

@app.get(f"{API_ROUTER_V1_PREFIX}/users/me", response_model=schemas.UserPublic, tags=["Users"])
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    """Get current authenticated user's details."""
    return current_user

@app.get(f"{API_ROUTER_V1_PREFIX}/users", response_model=List[schemas.UserPublic], tags=["Users"])
async def read_all_users(
    skip: int = 0, limit: int = 100,
    db: AsyncSession = Depends(get_db_session),
    _admin_user: models.User = Depends(get_current_active_admin_user) # Protected: only admins
):
    """Retrieve all users (admin only)."""
    users = await crud.get_users(db, skip=skip, limit=limit)
    return users

# Placeholder for health check
@app.get("/health", status_code=200)
async def health_check():
    return {"status": "healthy"}

# Mount Prometheus metrics app
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)
