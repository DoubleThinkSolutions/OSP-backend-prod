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

    # --- NEW: Link to the owning user ---
    owner_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="devices")

    # --- DEPRECATED: Remove APIKey relationship ---
    # api_key_entry = relationship("APIKey", back_populates="device", uselist=False, cascade="all, delete-orphan")

    manifests = relationship("Manifest", back_populates="device")

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
    is_superuser = Column(Boolean, default=False)
    role = Column(String, default="user", nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    # Add the relationship to devices owned by this user
    devices = relationship("Device", back_populates="owner")
