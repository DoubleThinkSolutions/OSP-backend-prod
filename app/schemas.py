# app/schemas.py
from pydantic import BaseModel, Field, validator, UUID4 # Import UUID4 for Pydantic
from typing import List, Dict, Any, Optional
import datetime as dt

# --- Base Schemas (for common fields like ID, created_at) ---
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True # Replaces orm_mode = True for Pydantic V2+
        populate_by_name = True # Allows using alias for field names

# --- Device Schemas ---
class DeviceBase(BaseSchema):
    device_id_str: str = Field(..., description="Unique string identifier for the device")
    description: Optional[str] = None

class DeviceCreate(DeviceBase):
    pass # No extra fields for creation initially

class DeviceUpdate(DeviceBase):
    description: Optional[str] = None
    is_active: Optional[bool] = None

class DeviceInDB(DeviceBase):
    id: UUID4 # Internal UUID primary key
    created_at: dt.datetime
    last_seen_at: dt.datetime
    is_active: bool

# --- GPS Schemas ---
class GPSSchema(BaseSchema):
    lat: Optional[float] = Field(None, ge=-90, le=90)
    lon: Optional[float] = Field(None, ge=-180, le=180)
    alt_m: Optional[float] = None
    acc_m: Optional[float] = Field(None, ge=0)

# --- Segment Schemas ---
class SegmentBase(BaseSchema):
    segment_index: int = Field(..., ge=0)
    client_filename: Optional[str] = Field(None, description="Filename of the segment as reported by client")
    sha256_hash_client: str = Field(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    duration_sec: float = Field(..., gt=0)
    totp_codes_json: List[str] # Will be stored as JSON in DB, but API expects/returns list

class SegmentCreate(SegmentBase):
    pass # Data comes from ManifestCreate's segments_data

class SegmentInDB(SegmentBase):
    id: UUID4
    manifest_id: UUID4
    sha256_hash_server: Optional[str] = None
    storage_type: Optional[str] = None
    storage_path_uri: Optional[str] = None
    file_size_bytes: Optional[int] = None
    hash_verified_status: Optional[str] = None
    created_at: dt.datetime

# --- Manifest Schemas ---
class ManifestBase(BaseSchema):
    manifest_client_id: Optional[str] = Field(None, description="Optional client-generated ID for idempotency")
    schema_version: str = Field("2.0-prod", description="Schema version of this manifest") # Updated version
    created_at_client: dt.datetime # Expect ISO string, Pydantic converts
    device_id_str: str = Field(..., description="Device string identifier that created this manifest")
    
    input_video_processed_client: Optional[str] = None
    gps_latitude: Optional[float] = Field(None, ge=-90, le=90)
    gps_longitude: Optional[float] = Field(None, ge=-180, le=180)
    gps_altitude_m: Optional[float] = None
    gps_accuracy_m: Optional[float] = Field(None, ge=0)
    
    segments_summary_json: Optional[Dict[str, Any]] = Field(None, description="Summary of all segments in this batch")

class ManifestCreate(ManifestBase):
    # When creating a manifest, we expect the segment data to be part of it.
    # The actual video files will be uploaded separately or as part of a multipart request.
    segments_data: List[SegmentCreate] # List of segment metadata

    @validator('created_at_client', pre=True)
    def parse_client_timestamp(cls, value):
        if isinstance(value, str):
            try:
                # Handle Z for UTC
                if value.endswith('Z'):
                    value = value[:-1] + '+00:00'
                return dt.datetime.fromisoformat(value)
            except ValueError:
                raise ValueError("Invalid ISO 8601 timestamp format for created_at_client")
        return value # Assume already datetime if not string

class ManifestInDB(ManifestBase):
    id: UUID4 # Internal DB ID
    device_db_id: UUID4
    received_at_server: dt.datetime
    server_verification_status: str
    overall_trust_score: Optional[float] = None
    segments: List[SegmentInDB] = [] # Include related segments when fetching a manifest

class ManifestIngestionResponse(BaseSchema):
    manifest_id: UUID4
    message: str
    received_at_server: dt.datetime
    # Could add URLs for next steps, e.g., where to upload segment files if not done in same request
    # For now, assume segments are described and files come with or shortly after.

# Schema for submitting manifest JSON along with file(s)
class ManifestFileSubmit(BaseModel):
    manifest_json_str: str # The manifest content as a JSON string

# --- Query Parameter Schemas ---
class ManifestQueryFilters(BaseModel):
    device_id_str: Optional[str] = Field(None, description="Filter by device string ID")
    server_verification_status: Optional[str] = Field(None, description="Filter by verification status")
    start_date_client: Optional[dt.datetime] = Field(None, description="Filter manifests created by client on or after this UTC datetime")
    end_date_client: Optional[dt.datetime] = Field(None, description="Filter manifests created by client on or before this UTC datetime")
    min_trust_score: Optional[float] = Field(None, ge=0, le=1, description="Minimum overall trust score")
    
    @validator('start_date_client', 'end_date_client', pre=True)
    def parse_query_datetimes(cls, value):
        if isinstance(value, str):
            try:
                if value.endswith('Z'): value = value[:-1] + '+00:00'
                return dt.datetime.fromisoformat(value)
            except ValueError:
                raise ValueError("Invalid ISO 8601 timestamp for date filter")
        return value # Assume already datetime

class SegmentQueryFilters(BaseModel):
    manifest_id: Optional[UUID4] = Field(None, description="Filter segments by manifest DB ID")
    segment_index: Optional[int] = Field(None, ge=0, description="Filter by specific segment index")
    hash_verified_status: Optional[str] = Field(None, description="Filter by hash verification status")
    storage_type: Optional[str] = Field(None, description="Filter by storage type")

# --- API Key Schemas ---
class APIKeyBase(BaseSchema):
    prefix: str # For display/identification
    is_active: bool = True
    expires_at: Optional[dt.datetime] = None
    description: Optional[str] = None

class APIKeyCreateInternal(BaseModel): # Used internally, not exposed directly via API for creation
    hashed_key: str
    prefix: str
    device_db_id: UUID4
    is_active: bool = True
    expires_at: Optional[dt.datetime] = None
    description: Optional[str] = None

class APIKeyInDB(APIKeyBase):
    id: UUID4
    device_db_id: UUID4 # So we know which device it belongs to if fetching keys directly
    created_at: dt.datetime
    last_used_at: Optional[dt.datetime] = None

# --- Device Registration / Key Issuance (Example - more complex in reality) ---
class DeviceRegistrationRequest(BaseModel):
    device_id_str: str = Field(..., description="Proposed unique string identifier for the new device")
    description: Optional[str] = None
    # In a real system, might include a public key for the device, attestation data, etc.

class DeviceRegistrationResponse(DeviceInDB): # Inherit DeviceInDB fields
    api_key: str = Field(..., description="The newly generated API key for the device. STORE THIS SECURELY. It will not be shown again.")
    api_key_prefix: str # Show prefix for identification

# --- User Schemas ---
class UserBase(BaseSchema):
    email: str = Field(..., example="user@example.com")
    full_name: Optional[str] = Field(None, example="John Doe")
    role: str = Field("user", description="User role (e.g., 'user', 'admin')")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="User password (min 8 characters)")

class UserUpdate(BaseSchema): # More restrictive on what can be updated
    email: Optional[str] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    # Password update should be a separate endpoint for security

class UserInDBBase(UserBase): # Base for user data stored in DB (without password)
    id: UUID4
    is_active: bool
    is_superuser: bool # For backward compatibility if some logic uses it
    created_at: dt.datetime
    updated_at: dt.datetime

class UserPublic(UserInDBBase): # What's generally safe to return about a user
    pass

class UserInternal(UserInDBBase): # Includes hashed_password for internal use
    hashed_password: str

# --- Token Schemas (for OAuth2/JWT) ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel): # Content of the JWT token payload (standard fields)
    sub: Optional[str] = None # "subject", typically username or user ID
    scopes: List[str] = [] # For scope-based authorization