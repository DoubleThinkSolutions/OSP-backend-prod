# app/crud.py
import uuid
import datetime as dt
from typing import List, Optional, Sequence # Added Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select # For SQLAlchemy 2.0 style select
from sqlalchemy.orm import selectinload # For eager loading relationships

from app import models, schemas, security

# --- Device CRUD ---
async def get_device_by_db_id(db: AsyncSession, device_db_id: uuid.UUID) -> Optional[models.Device]:
    """Get a device by its internal database UUID."""
    result = await db.execute(select(models.Device).filter(models.Device.id == device_db_id))
    return result.scalar_one_or_none()

async def get_device_by_str_id(db: AsyncSession, device_id_str: str) -> Optional[models.Device]:
    """Get a device by its string identifier (device_id_str)."""
    result = await db.execute(select(models.Device).filter(models.Device.device_id_str == device_id_str))
    return result.scalar_one_or_none()

async def create_device_with_api_key(
    db: AsyncSession, 
    device_create_schema: schemas.DeviceCreate # Using DeviceCreate which just has device_id_str and description
) -> Tuple[models.Device, str]: # Returns (Device, raw_api_key)
    """Create a new device and its initial API key. Returns the raw key once."""
    
    # 1. Create the device
    db_device = models.Device(
        device_id_str=device_create_schema.device_id_str,
        description=device_create_schema.description,
        created_at=dt.datetime.utcnow(),
        last_seen_at=dt.datetime.utcnow(),
        is_active=True
    )
    db.add(db_device)
    await db.flush([db_device]) # Ensure device.id is populated

    # 2. Generate and store API key for this device
    raw_api_key, prefix, hashed_key = security.generate_api_key_and_hash()
    await create_api_key_for_device(
        db, 
        device_db_id=db_device.id, 
        hashed_key=hashed_key, 
        prefix=prefix,
        description=f"Primary key for device {db_device.device_id_str}"
    )
    # The APIKey object is linked to db_device via relationship back_populates
    # We might need to refresh db_device if we want to see api_key_entry populated immediately
    # await db.refresh(db_device, ["api_key_entry"]) # If needed

    return db_device, raw_api_key

async def get_or_create_device_with_api_key_check(
    db: AsyncSession,
    device_id_str: str,
    provided_api_key: str, # The raw key provided by the client
    description: Optional[str] = None
) -> Optional[models.Device]:
    """
    Gets a device if it exists AND the provided API key is valid for it.
    This is more for ongoing authentication than creation.
    For creation, use a separate registration endpoint.
    This function primarily AUTHENTICATES a device.
    """
    # API keys are short-lived, don't include them directly in API request for get/create device
    # Client authenticates with X-DEVICE-API-KEY header.
    # This function is more conceptual for how an auth check works.
    # The actual auth is done by the `verify_device_api_key` dependency.
    # This function could be used by `verify_device_api_key` internally.

    # Extract prefix from the provided_api_key
    key_prefix = provided_api_key[:security.API_KEY_PREFIX_LENGTH]
    db_api_key_entry = await get_api_key_by_prefix(db, prefix=key_prefix)

    if db_api_key_entry and db_api_key_entry.is_active and db_api_key_entry.device:
        if db_api_key_entry.device.device_id_str == device_id_str: # Ensure key belongs to this device_id_str
            if security.verify_api_key(provided_api_key, db_api_key_entry.hashed_key):
                # Key is valid for this device
                db_api_key_entry.device.last_seen_at = dt.datetime.utcnow()
                await update_api_key_last_used(db, db_api_key_entry.id)
                # db.add(db_api_key_entry.device) # Mark as dirty
                return db_api_key_entry.device
    return None

async def get_devices(db: AsyncSession, skip: int = 0, limit: int = 100) -> Sequence[models.Device]:
    """Retrieve multiple devices with pagination."""
    result = await db.execute(select(models.Device).offset(skip).limit(limit))
    return result.scalars().all()


# --- Manifest CRUD ---
async def create_manifest(db: AsyncSession, manifest: schemas.ManifestCreate, device_db_id: uuid.UUID) -> models.Manifest:
    """Create a new manifest."""
    db_manifest = models.Manifest(
        manifest_client_id=manifest.manifest_client_id,
        device_db_id=device_db_id, # Use the internal DB ID of the device
        schema_version=manifest.schema_version,
        created_at_client=manifest.created_at_client, # Already datetime from Pydantic
        received_at_server=dt.datetime.utcnow(),
        input_video_processed_client=manifest.input_video_processed_client,
        gps_latitude=manifest.gps_latitude,
        gps_longitude=manifest.gps_longitude,
        gps_altitude_m=manifest.gps_altitude_m,
        gps_accuracy_m=manifest.gps_accuracy_m,
        segments_summary_json=manifest.segments_summary_json,
        server_verification_status="RECEIVED_PENDING_PROCESSING", # Initial status
        # overall_trust_score will be calculated later
    )
    db.add(db_manifest)
    await db.flush([db_manifest]) # Flush to get the db_manifest.id for segments
    return db_manifest

async def get_manifest(db: AsyncSession, manifest_id: uuid.UUID) -> Optional[models.Manifest]:
    """Retrieve a manifest by its ID, including its related segments."""
    result = await db.execute(
        select(models.Manifest)
        .options(selectinload(models.Manifest.segments)) # Eager load segments
        .filter(models.Manifest.id == manifest_id)
    )
    return result.scalar_one_or_none()

async def get_manifests(db: AsyncSession, skip: int = 0, limit: int = 100) -> Sequence[models.Manifest]:
    """Retrieve multiple manifests with pagination, including their segments."""
    result = await db.execute(
        select(models.Manifest)
        .options(selectinload(models.Manifest.segments)) # Eager load segments
        .order_by(models.Manifest.received_at_server.desc()) # Example ordering
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()

async def update_manifest_status(db: AsyncSession, manifest_id: uuid.UUID, status: str, trust_score: Optional[float] = None) -> Optional[models.Manifest]:
    """Update the status and optionally trust score of a manifest."""
    db_manifest = await get_manifest(db, manifest_id=manifest_id) # get_manifest already eager loads segments
    if db_manifest:
        db_manifest.server_verification_status = status
        if trust_score is not None:
            db_manifest.overall_trust_score = trust_score
        # db.add(db_manifest) # Mark as dirty if needed
        await db.flush([db_manifest]) # Ensure changes are flushed
        return db_manifest
    return None

# --- Segment CRUD ---
async def create_segment(
    db: AsyncSession,
    segment: schemas.SegmentCreate, # This is schemas.SegmentBase effectively, via ManifestCreate
    manifest_id: uuid.UUID,
    storage_path_uri: str,
    storage_type: str,
    file_size_bytes: int
) -> models.Segment:
    """Create a new segment associated with a manifest."""
    db_segment = models.Segment(
        manifest_id=manifest_id,
        segment_index=segment.segment_index,
        client_filename=segment.client_filename,
        sha256_hash_client=segment.sha256_hash_client,
        duration_sec=segment.duration_sec,
        totp_codes_json=segment.totp_codes_json, # Already a list from Pydantic schema
        storage_path_uri=storage_path_uri,
        storage_type=storage_type,
        file_size_bytes=file_size_bytes,
        hash_verified_status="PENDING_SERVER_HASH", # Initial status
        created_at=dt.datetime.utcnow()
    )
    db.add(db_segment)
    await db.flush([db_segment]) # Flush to get segment ID if needed immediately
    return db_segment

async def get_segment(db: AsyncSession, segment_id: uuid.UUID) -> Optional[models.Segment]:
    """Retrieve a segment by its ID."""
    result = await db.execute(select(models.Segment).filter(models.Segment.id == segment_id))
    return result.scalar_one_or_none()

async def get_segments_for_manifest(db: AsyncSession, manifest_id: uuid.UUID) -> Sequence[models.Segment]:
    """Retrieve all segments for a given manifest."""
    result = await db.execute(
        select(models.Segment)
        .filter(models.Segment.manifest_id == manifest_id)
        .order_by(models.Segment.segment_index)
    )
    return result.scalars().all()

async def update_segment_server_hash(
    db: AsyncSession,
    segment_id: uuid.UUID,
    server_hash: str,
    hash_status: str # e.g., "MATCH", "MISMATCH"
) -> Optional[models.Segment]:
    """Update a segment's server-calculated hash and verification status."""
    db_segment = await get_segment(db, segment_id=segment_id)
    if db_segment:
        db_segment.sha256_hash_server = server_hash
        db_segment.hash_verified_status = hash_status
        # db.add(db_segment)
        await db.flush([db_segment])
        return db_segment
    return None

# --- APIKey CRUD ---
async def create_api_key_for_device(
    db: AsyncSession, 
    device_db_id: uuid.UUID, 
    hashed_key: str, 
    prefix: str,
    description: Optional[str] = "Device API Key",
    expires_at: Optional[dt.datetime] = None
) -> models.APIKey:
    db_api_key = models.APIKey(
        device_db_id=device_db_id,
        hashed_key=hashed_key,
        prefix=prefix,
        description=description,
        expires_at=expires_at,
        is_active=True
    )
    db.add(db_api_key)
    await db.flush([db_api_key]) # Ensure ID is populated
    return db_api_key

async def get_api_key_by_prefix(db: AsyncSession, prefix: str) -> Optional[models.APIKey]:
    """Retrieve an API key entry by its prefix (for initial lookup)."""
    result = await db.execute(
        select(models.APIKey)
        .options(selectinload(models.APIKey.device)) # Eager load device
        .filter(models.APIKey.prefix == prefix)
    )
    return result.scalar_one_or_none()

async def update_api_key_last_used(db: AsyncSession, api_key_id: uuid.UUID):
    """Update the last_used_at timestamp for an API key."""
    stmt = (
        update(models.APIKey)
        .where(models.APIKey.id == api_key_id)
        .values(last_used_at=dt.datetime.utcnow())
        .execution_options(synchronize_session="fetch") # To update session objects
    )
    await db.execute(stmt)
    # No need to commit here, session manager handles it.

async def deactivate_api_key(db: AsyncSession, api_key_id: uuid.UUID) -> Optional[models.APIKey]:
    db_api_key = await db.get(models.APIKey, api_key_id) # Simpler get by PK
    if db_api_key:
        db_api_key.is_active = False
        db_api_key.last_used_at = dt.datetime.utcnow() # Also update last used
        # db.add(db_api_key)
        await db.flush([db_api_key])
        return db_api_key
    return None

# --- User CRUD ---
async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> Optional[models.User]:
    result = await db.execute(select(models.User).filter(models.User.id == user_id))
    return result.scalar_one_or_none()

async def get_user_by_email(db: AsyncSession, email: str) -> Optional[models.User]:
    result = await db.execute(select(models.User).filter(models.User.email == email))
    return result.scalar_one_or_none()

async def create_user(db: AsyncSession, user: schemas.UserCreate) -> models.User:
    hashed_password = security.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        role=user.role.lower(), # Store role consistently
        is_active=True, # Default new users to active
        is_superuser=False # Default new users to not superuser
    )
    db.add(db_user)
    await db.flush([db_user]) # Ensure ID is populated
    return db_user

async def update_user(db: AsyncSession, db_user: models.User, user_in: schemas.UserUpdate) -> models.User:
    update_data = user_in.model_dump(exclude_unset=True) # Pydantic V2
    if "email" in update_data:
        db_user.email = update_data["email"]
    if "full_name" in update_data:
        db_user.full_name = update_data["full_name"]
    if "is_active" in update_data:
        db_user.is_active = update_data["is_active"]
    # Password updates should be handled by a separate, dedicated function/endpoint
    
    db_user.updated_at = dt.datetime.utcnow()
    # db.add(db_user)
    await db.flush([db_user])
    return db_user

async def get_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> Sequence[models.User]:
    result = await db.execute(
        select(models.User).order_by(models.User.email).offset(skip).limit(limit)
    )
    return result.scalars().all()