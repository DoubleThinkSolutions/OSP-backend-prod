# app/services/file_service.py
import os
import uuid
import hashlib
import asyncio
from fastapi import UploadFile, HTTPException
from typing import Tuple, Optional, AsyncGenerator, AsyncIterator # Add AsyncIterator

import aioboto3 # For asynchronous S3 operations
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

from app.core.config import settings

class FileStorageService:
    def __init__(self):
        self.s3_enabled = settings.S3_ENABLED and settings.is_s3_configured()
        if self.s3_enabled:
            print("[FileService] S3/MinIO storage is ENABLED.")
            # Session can be created per request or once if thread-safe (aioboto3 sessions are generally okay)
            # Creating it here means it's shared, which is usually fine.
            self.session = aioboto3.Session(
                aws_access_key_id=settings.S3_ACCESS_KEY_ID,
                aws_secret_access_key=settings.S3_SECRET_ACCESS_KEY,
                region_name=settings.S3_REGION_NAME
            )
        else:
            print("[FileService] S3/MinIO storage is DISABLED. Using local temporary storage.")
            self.base_upload_dir = settings.TEMP_UPLOAD_DIR
            if not os.path.exists(self.base_upload_dir):
                os.makedirs(self.base_upload_dir, exist_ok=True)

    async def get_stored_file_content_and_hash(
        self,
        storage_key_uri: str, # e.g., "s3://bucket/key" or "file:///path/to/file"
        storage_type: str # e.g., "S3_COMPATIBLE:bucket-name" or "LOCAL_TEMP_SIMULATING_OBJECT_STORAGE"
    ) -> Tuple[Optional[AsyncIterator[bytes]], Optional[str]]: # Returns (content_stream, sha256_hash)
        """
        Retrieves the content of a stored file as an async iterator and calculates its SHA256 hash.
        Returns (None, None) if the file cannot be accessed or an error occurs.
        """
        sha256_hash_obj = hashlib.sha256()
        
        async def content_iterator_wrapper(source_iterator: AsyncIterator[bytes]):
            """Wraps the source iterator to also update the hash."""
            async for chunk in source_iterator:
                sha256_hash_obj.update(chunk)
                yield chunk
        
        try:
            if storage_type.startswith("S3_COMPATIBLE") and self.s3_enabled:
                # Extract bucket and key from storage_key_uri
                if not storage_key_uri.startswith("s3://"):
                    raise ValueError("Invalid S3 URI format")
                
                parts = storage_key_uri[5:].split('/', 1)
                if len(parts) < 2:
                    raise ValueError("S3 URI missing key after bucket name")
                
                bucket_name = parts[0]
                object_key = parts[1]

                # This check ensures we're using the configured bucket if the URI is generic
                if bucket_name != settings.S3_BUCKET_NAME:
                    print(f"[FileService WARNING] Mismatch between URI bucket '{bucket_name}' and settings bucket '{settings.S3_BUCKET_NAME}'. Using settings bucket.")
                    # bucket_name = settings.S3_BUCKET_NAME # Or raise error

                async with self.session.client("s3", endpoint_url=settings.S3_ENDPOINT_URL, use_ssl=settings.S3_USE_SSL) as s3_client:
                    s3_object = await s3_client.get_object(Bucket=bucket_name, Key=object_key)
                    # s3_object['Body'] is an AiobotocoreStreamingBody, which is an async iterator
                    return content_iterator_wrapper(s3_object['Body']), None # Hash will be calculated after iteration
            
            elif storage_type.startswith("LOCAL_TEMP") or storage_type.startswith("file://"):
                if storage_key_uri.startswith("file://"):
                    local_file_path = storage_key_uri[7:]
                elif storage_key_uri.startswith("local_temp_mock_s3_key://"): # Path from earlier local save
                    # This implies the key was <device>/<manifest>/<file_id_name>
                    # Reconstruct local path based on this convention
                    # This is a bit fragile if the convention in save_upload_file changes.
                    # Ideally, storage_key_uri for local files should just be the absolute path.
                    # Let's assume for now it's the direct path from the save function.
                    # For `local_temp_mock_s3_key://<device_id>/<manifest_id>/<file_id_name>`
                    # the actual local path was `base_upload_dir/<device_id>/<manifest_id>/<file_id_name>` (with os.sep)
                    key_parts = storage_key_uri[len("local_temp_mock_s3_key://"):].split('/')
                    if len(key_parts) == 3: # device_id / manifest_id / actual_file_name
                         local_file_path = os.path.join(self.base_upload_dir, key_parts[0], key_parts[1], key_parts[2])
                    else: # Fallback if key structure is different, assume it's a direct relative path in base_upload_dir
                         local_file_path = os.path.join(self.base_upload_dir, storage_key_uri[len("local_temp_mock_s3_key://"):])

                else: # Assume it's an absolute path if no known prefix
                    local_file_path = storage_key_uri

                if not os.path.exists(local_file_path):
                    print(f"[FileService] Local file not found at: {local_file_path}")
                    return None, None

                async def local_file_chunk_iterator(file_path, chunk_size=1024*1024):
                    with open(file_path, "rb") as f:
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            yield chunk
                            await asyncio.sleep(0) # Yield control to event loop for large files

                return content_iterator_wrapper(local_file_chunk_iterator(local_file_path)), None
            
            else:
                print(f"[FileService] Unknown storage type: {storage_type} for key: {storage_key_uri}")
                return None, None
                
        except Exception as e:
            print(f"[FileService] Error getting file content for '{storage_key_uri}': {e}")
            return None, None
        
        # Note: The actual hash is calculated by the caller iterating through the stream.
        # This function structure is a bit tricky. Let's refine.
        # The goal is: stream content AND get final hash.

    async def calculate_hash_of_stored_file(self, storage_key_uri: str, storage_type: str) -> Optional[str]:
        """Calculates SHA256 hash of a stored file by streaming its content."""
        content_stream_wrapper, _ = await self.get_stored_file_content_and_hash(storage_key_uri, storage_type)
        
        if not content_stream_wrapper:
            return None
            
        sha256_hash_obj = hashlib.sha256()
        # The content_stream_wrapper from get_stored_file_content_and_hash has the hash object embedded.
        # This is not ideal. Let's simplify get_stored_file_content_and_hash to just return the stream,
        # and this function does the hashing.

        # Revised approach:
        _sha256_hash_obj_for_calc = hashlib.sha256()
        try:
            if storage_type.startswith("S3_COMPATIBLE") and self.s3_enabled:
                if not storage_key_uri.startswith("s3://"): raise ValueError("Invalid S3 URI")
                parts = storage_key_uri[5:].split('/', 1)
                if len(parts) < 2: raise ValueError("S3 URI missing key")
                bucket_name, object_key = parts[0], parts[1]
                # if bucket_name != settings.S3_BUCKET_NAME: bucket_name = settings.S3_BUCKET_NAME

                async with self.session.client("s3", endpoint_url=settings.S3_ENDPOINT_URL, use_ssl=settings.S3_USE_SSL) as s3_client:
                    s3_object = await s3_client.get_object(Bucket=bucket_name, Key=object_key)
                    async for chunk in s3_object['Body']:
                        _sha256_hash_obj_for_calc.update(chunk)
                    return _sha256_hash_obj_for_calc.hexdigest()

            elif storage_type.startswith("LOCAL_TEMP") or storage_type.startswith("file://"):
                # ... (path reconstruction logic as above) ...
                if storage_key_uri.startswith("file://"): local_file_path = storage_key_uri[7:]
                elif storage_key_uri.startswith("local_temp_mock_s3_key://"):
                    key_parts = storage_key_uri[len("local_temp_mock_s3_key://"):].split('/')
                    local_file_path = os.path.join(self.base_upload_dir, *key_parts) if len(key_parts) <=3 else os.path.join(self.base_upload_dir, key_parts[-1]) # Simplified
                else: local_file_path = storage_key_uri
                
                if not os.path.exists(local_file_path): return None
                with open(local_file_path, "rb") as f:
                    while True:
                        chunk = f.read(1024 * 1024) # 1MB chunk
                        if not chunk: break
                        _sha256_hash_obj_for_calc.update(chunk)
                return _sha256_hash_obj_for_calc.hexdigest()
            else:
                return None
        except Exception as e:
            print(f"[FileService] Error calculating hash for '{storage_key_uri}': {e}")
            return None

    async def _ensure_bucket_exists(self):
        """Helper to create bucket if it doesn't exist (useful for MinIO)."""
        if not self.s3_enabled: return
        try:
            async with self.session.client("s3", endpoint_url=settings.S3_ENDPOINT_URL, use_ssl=settings.S3_USE_SSL) as s3_client:
                await s3_client.head_bucket(Bucket=settings.S3_BUCKET_NAME)
                print(f"[FileService] S3 Bucket '{settings.S3_BUCKET_NAME}' found.")
        except ClientError as e:
            if e.response['Error']['Code'] == '404': # Not found
                print(f"[FileService] S3 Bucket '{settings.S3_BUCKET_NAME}' not found. Attempting to create...")
                try:
                    # For AWS S3, region might be needed if not us-east-1 for bucket creation
                    # For MinIO, LocationConstraint is often not needed or should match MinIO's region if set.
                    create_bucket_config = {}
                    if settings.S3_REGION_NAME and "amazonaws.com" in (settings.S3_ENDPOINT_URL or "") and settings.S3_REGION_NAME != "us-east-1":
                         create_bucket_config['CreateBucketConfiguration'] = {'LocationConstraint': settings.S3_REGION_NAME}
                    
                    await s3_client.create_bucket(Bucket=settings.S3_BUCKET_NAME, **create_bucket_config)
                    print(f"[FileService] S3 Bucket '{settings.S3_BUCKET_NAME}' created successfully.")
                except Exception as create_e:
                    print(f"[FileService CRITICAL] Could not create S3 bucket '{settings.S3_BUCKET_NAME}': {create_e}")
                    raise # Propagate error if bucket creation fails
            elif e.response['Error']['Code'] == '403': # Forbidden
                print(f"[FileService CRITICAL] Access forbidden to S3 bucket '{settings.S3_BUCKET_NAME}'. Check credentials and permissions.")
                raise
            else:
                print(f"[FileService CRITICAL] Error checking S3 bucket: {e}")
                raise

    async def _read_uploadfile_in_chunks(self, upload_file: UploadFile, chunk_size=1024*1024) -> AsyncGenerator[bytes, None]:
        """Reads UploadFile in chunks asynchronously."""
        while content_chunk := await upload_file.read(chunk_size):
            yield content_chunk

    async def save_upload_file(
        self,
        upload_file: UploadFile,
        device_id_str: str,
        manifest_db_id: uuid.UUID,
        segment_index: int # For more specific object key
    ) -> Tuple[str, int, str, str]: # Returns: storage_key, file_size, sha256_hash, storage_type
        """
        Saves an uploaded file. If S3 is enabled, uploads to S3/MinIO.
        Otherwise, saves to local temporary directory.
        Calculates SHA256 hash during read/upload.

        Returns:
            Tuple (storage_key_uri, file_size_bytes, sha256_hash_server, storage_type_indicator)
        """
        file_id = str(uuid.uuid4())
        original_filename = upload_file.filename if upload_file.filename else f"segment_{segment_index}"
        safe_original_filename = "".join(
            c for c in original_filename if c.isalnum() or c in ['.', '_', '-']
        ).strip()
        if not safe_original_filename:
            safe_original_filename = f"segment_{segment_index}"
        
        # Object key for S3/MinIO or path suffix for local
        object_key_suffix = f"{file_id}_{safe_original_filename}"
        # Full object key: e.g., <device_id_str>/<manifest_db_id_str>/<object_key_suffix>
        object_key = os.path.join(device_id_str, str(manifest_db_id), object_key_suffix).replace(os.path.sep, '/')


        file_size_bytes = 0
        sha256_hash_obj = hashlib.sha256()

        storage_type_indicator = "LOCAL_TEMP"
        storage_key_uri = f"local_temp_mock_s3_key://{object_key}" # Default for local

        try:
            if self.s3_enabled:
                storage_type_indicator = f"S3_COMPATIBLE:{settings.S3_BUCKET_NAME}"
                storage_key_uri = f"s3://{settings.S3_BUCKET_NAME}/{object_key}"
                
                # Ensure bucket exists (call once or per upload based on strategy)
                # For this example, let's assume it's checked on service init or first use.
                # If doing it per upload: await self._ensure_bucket_exists()

                async with self.session.client("s3", endpoint_url=settings.S3_ENDPOINT_URL, use_ssl=settings.S3_USE_SSL) as s3_client:
                    # Upload using UploadFile's stream directly for efficiency with large files
                    # To do this and hash simultaneously, we need to read chunks
                    
                    # We need a way to stream UploadFile to S3's put_object Body (which can be a stream)
                    # and calculate hash. S3 put_object can take an async generator for Body.
                    
                    async def hashing_chunk_generator():
                        nonlocal file_size_bytes # Allow modification of outer scope variable
                        async for chunk in self._read_uploadfile_in_chunks(upload_file):
                            sha256_hash_obj.update(chunk)
                            file_size_bytes += len(chunk)
                            yield chunk
                    
                    await s3_client.put_object(
                        Bucket=settings.S3_BUCKET_NAME,
                        Key=object_key,
                        Body=hashing_chunk_generator() # Pass the async generator
                        # ContentLength=upload_file.size, # If available and reliable from client
                        # ContentType=upload_file.content_type
                    )
                print(f"[FileService] File '{original_filename}' uploaded to S3: {storage_key_uri}")
            else: # Fallback to local storage
                local_file_dir = os.path.join(self.base_upload_dir, device_id_str, str(manifest_db_id))
                if not os.path.exists(local_file_dir):
                    os.makedirs(local_file_dir, exist_ok=True)
                local_file_path = os.path.join(local_file_dir, object_key_suffix)
                storage_key_uri = f"file://{local_file_path}" # Actual local file URI

                with open(local_file_path, "wb") as buffer:
                    async for chunk in self._read_uploadfile_in_chunks(upload_file):
                        buffer.write(chunk)
                        sha256_hash_obj.update(chunk)
                        file_size_bytes += len(chunk)
                print(f"[FileService] File '{original_filename}' saved locally to '{local_file_path}'")

            sha256_hash_hex = sha256_hash_obj.hexdigest()
            print(f"    Size: {file_size_bytes} bytes, SHA256: {sha256_hash_hex[:8]}...")
            return storage_key_uri, file_size_bytes, sha256_hash_hex, storage_type_indicator

        except (NoCredentialsError, PartialCredentialsError):
            print("[FileService CRITICAL] S3 credentials not found or incomplete.")
            raise HTTPException(status_code=500, detail="S3 storage credentials error.")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            print(f"[FileService CRITICAL] S3 ClientError ({error_code}): {e}")
            raise HTTPException(status_code=500, detail=f"S3 storage error: {error_code}")
        except Exception as e:
            print(f"[FileService CRITICAL] Error saving/uploading file '{original_filename}': {e}")
            # Attempt to clean up (more complex for S3, would need to delete object if partially uploaded)
            # For local: if os.path.exists(local_file_path) and not self.s3_enabled: os.remove(local_file_path)
            raise HTTPException(status_code=500, detail=f"File processing error: {str(e)}")
        finally:
            await upload_file.close() # Ensure file is closed

    async def get_presigned_download_url(self, object_key: str, expires_in_seconds: int = 3600) -> Optional[str]:
        """Generates a presigned URL for downloading an object from S3/MinIO."""
        if not self.s3_enabled:
            # For local files, we could serve them via a dedicated FastAPI endpoint
            # or simply indicate that direct URL generation isn't supported for local_temp.
            # Returning the "file://" URI is an option, but not web-accessible.
            # This conceptual local path isn't directly usable as a web URL.
            # We'd need to map object_key back to the local structure.
            local_path_equivalent = os.path.join(self.base_upload_dir, object_key.replace('/', os.path.sep))
            if os.path.exists(local_path_equivalent):
                return f"local_file_access_not_presigned_url:{local_path_equivalent}" # Placeholder
            return None

        try:
            async with self.session.client("s3", endpoint_url=settings.S3_ENDPOINT_URL, use_ssl=settings.S3_USE_SSL) as s3_client:
                url = await s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': settings.S3_BUCKET_NAME, 'Key': object_key},
                    ExpiresIn=expires_in_seconds
                )
                return url
        except Exception as e:
            print(f"[FileService] Error generating presigned URL for '{object_key}': {e}")
            return None

    # TODO: Implement delete_file from S3/local

# Instantiate the service for use
file_storage_service = FileStorageService()

# Add an async function to be called on startup to ensure bucket exists
async def initialize_storage_service():
    if file_storage_service.s3_enabled:
        print("[Startup] Initializing S3 File Storage Service. Checking/Creating bucket...")
        await file_storage_service._ensure_bucket_exists() # Call the helper
    else:
        print("[Startup] File Storage Service initialized for local temporary storage.")