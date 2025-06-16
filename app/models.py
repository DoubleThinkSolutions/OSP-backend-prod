# app/models.py
import uuid
import datetime as dt
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, JSON, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID # For native UUID type in PostgreSQL
from app.database import Base

class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id_str = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_seen_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    is_active = Column(Boolean, default=True)

    manifests = relationship("Manifest", back_populates="device")
    # Change to one-to-one relationship with APIKey for this simplified model
    # If a device could have multiple keys, this would be a list (back_populates="api_keys")
    api_key_entry = relationship("APIKey", back_populates="device", uselist=False, cascade="all, delete-orphan")

class Manifest(Base):
    __tablename__ = "manifests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4) # Internal DB ID
    manifest_client_id = Column(String, index=True, nullable=True) # Optional client-generated ID for idempotency

    device_db_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False) # Link to internal Device PK
    
    schema_version = Column(String, nullable=False)
    created_at_client = Column(DateTime, nullable=False) # Timestamp from client
    received_at_server = Column(DateTime, default=dt.datetime.utcnow, nullable=False)
    
    input_video_processed_client = Column(String, nullable=True)
    gps_latitude = Column(Float, nullable=True)
    gps_longitude = Column(Float, nullable=True)
    gps_altitude_m = Column(Float, nullable=True)
    gps_accuracy_m = Column(Float, nullable=True)
    
    segments_summary_json = Column(JSON, nullable=True) # Store the segments_summary dict as JSON

    server_verification_status = Column(String, default="PENDING_VERIFICATION", index=True)
    overall_trust_score = Column(Float, nullable=True, index=True)

    # Relationship to Device
    device = relationship("Device", back_populates="manifests")
    # Relationship to Segments
    segments = relationship("Segment", back_populates="manifest", cascade="all, delete-orphan")


class Segment(Base):
    __tablename__ = "segments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    manifest_id = Column(UUID(as_uuid=True), ForeignKey("manifests.id"), nullable=False)
    
    segment_index = Column(Integer, nullable=False)
    client_filename = Column(String, nullable=True) # Filename as reported by client for this segment
    
    # Hashes
    sha256_hash_client = Column(String(64), nullable=False)
    sha256_hash_server = Column(String(64), nullable=True, index=True) # Calculated by server
    
    duration_sec = Column(Float, nullable=False)
    totp_codes_json = Column(JSON, nullable=False) # Store list of TOTP codes as JSON array
    
    # Storage info
    storage_type = Column(String, default="LOCAL_TEMP") # e.g., S3_MINIO, IPFS
    storage_path_uri = Column(String, nullable=True, index=True) # e.g., s3://bucket/path/to/file
    file_size_bytes = Column(Integer, nullable=True)

    # Verification & Trust
    hash_verified_status = Column(String, default="PENDING", index=True) # PENDING, MATCH, MISMATCH
    # totp_consistency_score = Column(Float, nullable=True)
    # telemetry_plausibility_score = Column(Float, nullable=True)
    # segment_trust_score = Column(Float, nullable=True)

    created_at = Column(DateTime, default=dt.datetime.utcnow)

    manifest = relationship("Manifest", back_populates="segments")

    # Add a unique constraint for manifest_id and segment_index
    # __table_args__ = (UniqueConstraint('manifest_id', 'segment_index', name='_manifest_segment_uc'),)
    # Note: For async, UniqueConstraint needs to be handled carefully or at DB level.
    # For now, application logic should ensure uniqueness before insertion.

class Segment(Base):
    __tablename__ = "segments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    manifest_id = Column(UUID(as_uuid=True), ForeignKey("manifests.id"), nullable=False)
    
    segment_index = Column(Integer, nullable=False)
    client_filename = Column(String, nullable=True)
    
    sha256_hash_client = Column(String(64), nullable=False)
    sha256_hash_server = Column(String(64), nullable=True, index=True) # Added
    
    duration_sec = Column(Float, nullable=False)
    totp_codes_json = Column(JSON, nullable=False)
    
    storage_type = Column(String, default="PENDING_STORAGE_ALLOCATION") # Updated default
    storage_path_uri = Column(String, nullable=True, index=True)
    file_size_bytes = Column(Integer, nullable=True)

    hash_verified_status = Column(String, default="PENDING_SERVER_CALC", index=True) # Updated default
    
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    manifest = relationship("Manifest", back_populates="segments")

class APIKey(Base): # New Model for API Keys
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hashed_key = Column(String(128), unique=True, index=True, nullable=False) # Store hash of the key
    prefix = Column(String(8), unique=True, nullable=False) # First few chars of the actual key for identification
    
    device_db_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, unique=True) # One key per device
    # Or, if a device can have multiple keys:
    # device_db_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    # __table_args__ = (UniqueConstraint('prefix', 'device_db_id', name='_device_apikey_prefix_uc'),)


    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True) # Optional expiry
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    description = Column(String, nullable=True) # e.g., "Device initial key"

    device = relationship("Device", back_populates="api_key_entry") # Changed from api_keys list

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False) # For admin privileges
    
    # Basic role field (could be an Enum or a separate Role table for more complexity)
    role = Column(String, default="user", nullable=False) # e.g., "user", "admin", "auditor"

    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    # Relationships (if users own devices or have specific permissions)
    # Example: devices = relationship("Device", back_populates="owner_user") # If users own devices