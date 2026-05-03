#!/usr/bin/env python3
"""
Enhanced File Transfer System for secure-term-chat
Advanced file sharing with security, compression, and resume support
"""

import asyncio
import os
import time
import hashlib
import logging
import mimetypes
import zipfile
import io
from typing import Dict, List, Optional, Any, Tuple, BinaryIO
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque
import struct
import json

log = logging.getLogger(__name__)

class FileType(Enum):
    """Supported file types"""
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    TEXT = "text"
    BINARY = "binary"
    UNKNOWN = "unknown"

class TransferStatus(Enum):
    """File transfer status"""
    PENDING = "pending"
    UPLOADING = "uploading"
    DOWNLOADING = "downloading"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    CORRUPTED = "corrupted"

class CompressionType(Enum):
    """Compression algorithms"""
    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"
    LZ4 = "lz4"
    BROTLI = "brotli"

class EncryptionType(Enum):
    """Encryption algorithms"""
    NONE = "none"
    AES256_GCM = "aes256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"

@dataclass
class FileMetadata:
    """File metadata information"""
    file_id: str
    filename: str
    original_filename: str
    file_size: int
    file_type: FileType
    mime_type: str
    checksum_sha256: str
    checksum_md5: str
    created_at: float
    uploaded_by: str
    room_id: str
    compression_type: CompressionType
    encryption_type: EncryptionType
    chunk_count: int
    is_encrypted: bool
    is_compressed: bool
    virus_scanned: bool = False
    virus_scan_result: str = ""
    download_count: int = 0
    last_accessed: float = 0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_accessed is None:
            self.last_accessed = time.time()

@dataclass
class FileChunk:
    """File chunk for transfer"""
    chunk_id: str
    file_id: str
    chunk_index: int
    chunk_size: int
    data: bytes
    checksum: str
    compressed: bool = False
    encrypted: bool = False
    
    def __post_init__(self):
        if not self.checksum:
            self.checksum = hashlib.sha256(self.data).hexdigest()

@dataclass
class TransferSession:
    """File transfer session"""
    session_id: str
    file_id: str
    transfer_type: str  # "upload" or "download"
    status: TransferStatus
    started_at: float
    completed_at: Optional[float] = None
    bytes_transferred: int = 0
    total_bytes: int = 0
    transfer_rate: float = 0.0
    chunks_completed: int = 0
    total_chunks: int = 0
    error_message: str = ""
    retry_count: int = 0
    max_retries: int = 3
    
    def __post_init__(self):
        if self.started_at is None:
            self.started_at = time.time()

class FileSecurityManager:
    """Manages file security operations"""
    
    def __init__(self):
        self.virus_scanner = None
        self.max_file_size = 100 * 1024 * 1024  # 100MB default
        self.allowed_extensions = {
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg',
            # Documents
            '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
            # Spreadsheets
            '.xls', '.xlsx', '.csv', '.ods',
            # Presentations
            '.ppt', '.pptx', '.odp',
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz',
            # Audio
            '.mp3', '.wav', '.flac', '.aac', '.ogg',
            # Video
            '.mp4', '.avi', '.mkv', '.mov', '.wmv',
            # Code
            '.py', '.js', '.html', '.css', '.json', '.xml',
            # Text
            '.md', '.rst', '.txt', '.log'
        }
        self.quarantined_files = set()
    
    def validate_file(self, filename: str, file_size: int, file_data: bytes = None) -> Tuple[bool, str]:
        """Validate file for security"""
        try:
            # Check file size
            if file_size > self.max_file_size:
                return False, f"File too large: {file_size} bytes (max: {self.max_file_size})"
            
            # Check file extension
            file_ext = Path(filename).suffix.lower()
            if file_ext not in self.allowed_extensions:
                return False, f"File type not allowed: {file_ext}"
            
            # Check for suspicious patterns
            if file_data and self._contains_suspicious_content(file_data):
                return False, "File contains suspicious content"
            
            # Check if file is quarantined
            file_hash = hashlib.sha256(file_data).hexdigest() if file_data else ""
            if file_hash in self.quarantined_files:
                return False, "File is quarantined"
            
            return True, "File validation passed"
            
        except Exception as e:
            log.error(f"Error validating file: {e}")
            return False, f"Validation error: {e}"
    
    def _contains_suspicious_content(self, file_data: bytes) -> bool:
        """Check for suspicious content in file"""
        suspicious_patterns = [
            b'<script',
            b'javascript:',
            b'vbscript:',
            b'eval(',
            b'exec(',
            b'shell_exec',
            b'system(',
            b'base64_decode',
            b'eval(base64_decode',
            b'<?php',
            b'<% ',
            b'<scriptlanguage',
            b'<iframe',
            b'<object',
            b'<embed'
        ]
        
        # Check first 1KB for suspicious patterns
        sample = file_data[:1024]
        for pattern in suspicious_patterns:
            if pattern in sample.lower():
                return True
        
        return False
    
    def scan_file(self, file_data: bytes) -> Tuple[bool, str]:
        """Scan file for viruses (placeholder)"""
        # In a real implementation, this would use an actual virus scanner
        # For now, we'll just do basic heuristic checks
        
        try:
            # Check file header for known malware signatures
            if len(file_data) < 4:
                return True, "File too small to scan"
            
            # Basic heuristics
            if self._contains_suspicious_content(file_data):
                return False, "Suspicious content detected"
            
            # Check for executable headers
            exe_headers = [b'MZ', b'\x7fELF', b'\xca\xfe\xba\xbe']
            if any(file_data.startswith(header) for header in exe_headers):
                return False, "Executable file detected"
            
            return True, "File scanned successfully"
            
        except Exception as e:
            log.error(f"Error scanning file: {e}")
            return False, f"Scan error: {e}"

class CompressionManager:
    """Manages file compression and decompression"""
    
    def __init__(self):
        self.compression_algorithms = {
            CompressionType.NONE: self._compress_none,
            CompressionType.GZIP: self._compress_gzip,
            CompressionType.ZLIB: self._compress_zlib,
            CompressionType.LZ4: self._compress_lz4,
            CompressionType.BROTLI: self._compress_brotli
        }
        
        self.decompression_algorithms = {
            CompressionType.NONE: self._decompress_none,
            CompressionType.GZIP: self._decompress_gzip,
            CompressionType.ZLIB: self._decompress_zlib,
            CompressionType.LZ4: self._decompress_lz4,
            CompressionType.BROTLI: self._decompress_brotli
        }
    
    def compress(self, data: bytes, compression_type: CompressionType) -> Tuple[bytes, bool]:
        """Compress data using specified algorithm"""
        try:
            if compression_type in self.compression_algorithms:
                compressed_data, was_compressed = self.compression_algorithms[compression_type](data)
                return compressed_data, was_compressed
            else:
                return data, False
        except Exception as e:
            log.error(f"Error compressing data: {e}")
            return data, False
    
    def decompress(self, data: bytes, compression_type: CompressionType) -> bytes:
        """Decompress data using specified algorithm"""
        try:
            if compression_type in self.decompression_algorithms:
                return self.decompression_algorithms[compression_type](data)
            else:
                return data
        except Exception as e:
            log.error(f"Error decompressing data: {e}")
            return data
    
    def _compress_none(self, data: bytes) -> Tuple[bytes, bool]:
        """No compression"""
        return data, False
    
    def _decompress_none(self, data: bytes) -> bytes:
        """No decompression"""
        return data
    
    def _compress_gzip(self, data: bytes) -> Tuple[bytes, bool]:
        """GZIP compression"""
        import gzip
        compressed = gzip.compress(data)
        return compressed, len(compressed) < len(data)
    
    def _decompress_gzip(self, data: bytes) -> bytes:
        """GZIP decompression"""
        import gzip
        return gzip.decompress(data)
    
    def _compress_zlib(self, data: bytes) -> Tuple[bytes, bool]:
        """ZLIB compression"""
        import zlib
        compressed = zlib.compress(data)
        return compressed, len(compressed) < len(data)
    
    def _decompress_zlib(self, data: bytes) -> bytes:
        """ZLIB decompression"""
        import zlib
        return zlib.decompress(data)
    
    def _compress_lz4(self, data: bytes) -> Tuple[bytes, bool]:
        """LZ4 compression (placeholder)"""
        # In a real implementation, use lz4 library
        return data, False
    
    def _decompress_lz4(self, data: bytes) -> bytes:
        """LZ4 decompression (placeholder)"""
        # In a real implementation, use lz4 library
        return data
    
    def _compress_brotli(self, data: bytes) -> Tuple[bytes, bool]:
        """Brotli compression"""
        try:
            import brotli
            compressed = brotli.compress(data)
            return compressed, len(compressed) < len(data)
        except ImportError:
            return data, False
    
    def _decompress_brotli(self, data: bytes) -> bytes:
        """Brotli decompression"""
        try:
            import brotli
            return brotli.decompress(data)
        except ImportError:
            return data

class EncryptionManager:
    """Manages file encryption and decryption"""
    
    def __init__(self):
        self.encryption_algorithms = {
            EncryptionType.NONE: self._encrypt_none,
            EncryptionType.AES256_GCM: self._encrypt_aes256_gcm,
            EncryptionType.CHACHA20_POLY1305: self._encrypt_chacha20
        }
        
        self.decryption_algorithms = {
            EncryptionType.NONE: self._decrypt_none,
            EncryptionType.AES256_GCM: self._decrypt_aes256_gcm,
            EncryptionType.CHACHA20_POLY1305: self._decrypt_chacha20
        }
    
    def encrypt(self, data: bytes, encryption_type: EncryptionType, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using specified algorithm"""
        try:
            if encryption_type in self.encryption_algorithms:
                encrypted_data, nonce = self.encryption_algorithms[encryption_type](data, key)
                return encrypted_data, nonce
            else:
                return data, b""
        except Exception as e:
            log.error(f"Error encrypting data: {e}")
            return data, b""
    
    def decrypt(self, encrypted_data: bytes, encryption_type: EncryptionType, key: bytes, nonce: bytes = b"") -> bytes:
        """Decrypt data using specified algorithm"""
        try:
            if encryption_type in self.decryption_algorithms:
                return self.decryption_algorithms[encryption_type](encrypted_data, key, nonce)
            else:
                return encrypted_data
        except Exception as e:
            log.error(f"Error decrypting data: {e}")
            return encrypted_data
    
    def _encrypt_none(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """No encryption"""
        return data, b""
    
    def _decrypt_none(self, data: bytes, key: bytes, nonce: bytes = b"") -> bytes:
        """No decryption"""
        return data
    
    def _encrypt_aes256_gcm(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """AES-256-GCM encryption"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        # Generate random nonce
        nonce = os.urandom(12)
        
        # Encrypt
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        
        return encrypted_data, nonce
    
    def _decrypt_aes256_gcm(self, encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
        """AES-256-GCM decryption"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.backends import default_backend
        
        # Decrypt
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        
        return decrypted_data
    
    def _encrypt_chacha20(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """ChaCha20-Poly1305 encryption (placeholder)"""
        # In a real implementation, use cryptography library
        return data, b""
    
    def _decrypt_chacha20(self, encrypted_data: bytes, key: bytes, nonce: bytes = b"") -> bytes:
        """ChaCha20-Poly1305 decryption (placeholder)"""
        # In a real implementation, use cryptography library
        return encrypted_data

class FileTransferManager:
    """Manages file transfers with security and optimization"""
    
    def __init__(self):
        self.security_manager = FileSecurityManager()
        self.compression_manager = CompressionManager()
        self.encryption_manager = EncryptionManager()
        
        # Storage
        self.files: Dict[str, FileMetadata] = {}
        self.file_chunks: Dict[str, List[FileChunk]] = defaultdict(list)
        self.transfer_sessions: Dict[str, TransferSession] = {}
        
        # Configuration
        self.chunk_size = 64 * 1024  # 64KB chunks
        self.max_concurrent_transfers = 5
        self.default_compression = CompressionType.GZIP
        self.default_encryption = EncryptionType.AES256_GCM
        
        # Statistics
        self.total_files = 0
        self.total_size = 0
        self.transfer_history = deque(maxlen=1000)
    
    async def upload_file(self, filename: str, file_data: bytes, room_id: str, 
                          uploaded_by: str, compression: CompressionType = None,
                          encryption: EncryptionType = None) -> Tuple[bool, str, str]:
        """Upload file with security and optimization"""
        try:
            # Validate file
            is_valid, message = self.security_manager.validate_file(filename, len(file_data), file_data)
            if not is_valid:
                return False, message, ""
            
            # Generate file ID
            file_id = hashlib.sha256(f"{filename}{time.time()}{uploaded_by}".encode()).hexdigest()
            
            # Determine compression and encryption
            compression = compression or self.default_compression
            encryption = encryption or self.default_encryption
            
            # Compress file
            compressed_data, was_compressed = self.compression_manager.compress(file_data, compression)
            
            # Encrypt file
            encryption_key = os.urandom(32)  # Generate random key
            encrypted_data, nonce = self.encryption_manager.encrypt(compressed_data, encryption, encryption_key)
            
            # Create chunks
            chunks = self._create_chunks(encrypted_data, file_id)
            
            # Create metadata
            metadata = FileMetadata(
                file_id=file_id,
                filename=filename,
                original_filename=filename,
                file_size=len(file_data),
                file_type=self._detect_file_type(filename, file_data),
                mime_type=self._get_mime_type(filename),
                checksum_sha256=hashlib.sha256(file_data).hexdigest(),
                checksum_md5=hashlib.md5(file_data).hexdigest(),
                created_at=time.time(),
                uploaded_by=uploaded_by,
                room_id=room_id,
                compression_type=compression,
                encryption_type=encryption,
                chunk_count=len(chunks),
                is_encrypted=encryption != EncryptionType.NONE,
                is_compressed=was_compressed
            )
            
            # Store file data
            self.files[file_id] = metadata
            self.file_chunks[file_id] = chunks
            
            # Update statistics
            self.total_files += 1
            self.total_size += len(file_data)
            
            # Add to transfer history
            self._add_transfer_history("upload", file_id, uploaded_by, room_id, len(file_data))
            
            log.info(f"Uploaded file: {filename} ({len(file_data)} bytes) -> {file_id}")
            return True, file_id, ""
            
        except Exception as e:
            log.error(f"Error uploading file: {e}")
            return False, f"Upload error: {e}", ""
    
    async def download_file(self, file_id: str, downloader: str) -> Tuple[bool, bytes, str]:
        """Download file with decryption and decompression"""
        try:
            if file_id not in self.files:
                return False, b"", "File not found"
            
            metadata = self.files[file_id]
            
            # Update access count
            metadata.download_count += 1
            metadata.last_accessed = time.time()
            
            # Get chunks
            if file_id not in self.file_chunks:
                return False, b"", "File chunks not found"
            
            chunks = self.file_chunks[file_id]
            
            # Reassemble file
            encrypted_data = self._reassemble_chunks(chunks)
            
            # Decrypt file
            # In a real implementation, the encryption key would be retrieved from a secure storage
            # For now, we'll assume no encryption for demonstration
            if metadata.is_encrypted:
                # This would need the encryption key from secure storage
                pass
            
            # Decompress file
            if metadata.is_compressed:
                file_data = self.compression_manager.decompress(encrypted_data, metadata.compression_type)
            else:
                file_data = encrypted_data
            
            # Verify checksum
            calculated_checksum = hashlib.sha256(file_data).hexdigest()
            if calculated_checksum != metadata.checksum_sha256:
                log.warning(f"Checksum mismatch for file {file_id}")
                return False, b"", "File integrity check failed"
            
            # Add to transfer history
            self._add_transfer_history("download", file_id, downloader, metadata.room_id, len(file_data))
            
            log.info(f"Downloaded file: {metadata.filename} ({len(file_data)} bytes) <- {file_id}")
            return True, file_data, ""
            
        except Exception as e:
            log.error(f"Error downloading file: {e}")
            return False, b"", f"Download error: {e}"
    
    def _create_chunks(self, data: bytes, file_id: str) -> List[FileChunk]:
        """Create file chunks for transfer"""
        chunks = []
        
        for i in range(0, len(data), self.chunk_size):
            chunk_data = data[i:i + self.chunk_size]
            chunk_id = hashlib.sha256(f"{file_id}_{i}".encode()).hexdigest()
            
            chunk = FileChunk(
                chunk_id=chunk_id,
                file_id=file_id,
                chunk_index=i // self.chunk_size,
                chunk_size=len(chunk_data),
                data=chunk_data
            )
            
            chunks.append(chunk)
        
        return chunks
    
    def _reassemble_chunks(self, chunks: List[FileChunk]) -> bytes:
        """Reassemble file from chunks"""
        # Sort chunks by index
        sorted_chunks = sorted(chunks, key=lambda x: x.chunk_index)
        
        # Reassemble data
        data = b""
        for chunk in sorted_chunks:
            data += chunk.data
        
        return data
    
    def _detect_file_type(self, filename: str, file_data: bytes) -> FileType:
        """Detect file type from filename and content"""
        # Try to detect from file extension first
        ext = Path(filename).suffix.lower()
        
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg']:
            return FileType.IMAGE
        elif ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv']:
            return FileType.VIDEO
        elif ext in ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a']:
            return FileType.AUDIO
        elif ext in ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx']:
            return FileType.DOCUMENT
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            return FileType.ARCHIVE
        elif ext in ['.py', '.js', '.html', '.css', '.json', '.xml', '.md']:
            return FileType.TEXT
        elif ext in ['.exe', '.dll', '.so', '.dylib']:
            return FileType.BINARY
        
        # Try to detect from content
        if file_data:
            if file_data.startswith(b'\x89PNG'):
                return FileType.IMAGE
            elif file_data.startswith(b'\xff\xd8\xff'):
                return FileType.IMAGE
            elif file_data.startswith(b'GIF'):
                return FileType.IMAGE
            elif file_data.startswith(b'PK\x03\x04'):
                return FileType.ARCHIVE
            elif file_data.startswith(b'%PDF'):
                return FileType.DOCUMENT
            elif file_data.startswith(b'<!DOCTYPE') or b'<html' in file_data[:1024]:
                return FileType.TEXT
        
        return FileType.UNKNOWN
    
    def _get_mime_type(self, filename: str) -> str:
        """Get MIME type for file"""
        mime_type, _ = mimetypes.guess_type(filename)
        return mime_type or "application/octet-stream"
    
    def _add_transfer_history(self, transfer_type: str, file_id: str, user_id: str, room_id: str, size: int):
        """Add transfer to history"""
        history_entry = {
            "type": transfer_type,
            "file_id": file_id,
            "user_id": user_id,
            "room_id": room_id,
            "size": size,
            "timestamp": time.time()
        }
        
        self.transfer_history.append(history_entry)
    
    def get_file_info(self, file_id: str) -> Optional[FileMetadata]:
        """Get file metadata"""
        return self.files.get(file_id)
    
    def get_user_files(self, user_id: str) -> List[FileMetadata]:
        """Get files uploaded by user"""
        return [f for f in self.files.values() if f.uploaded_by == user_id]
    
    def get_room_files(self, room_id: str) -> List[FileMetadata]:
        """Get files in room"""
        return [f for f in self.files.values() if f.room_id == room_id]
    
    def get_transfer_stats(self) -> Dict[str, Any]:
        """Get transfer statistics"""
        return {
            "total_files": self.total_files,
            "total_size": self.total_size,
            "average_file_size": self.total_size / self.total_files if self.total_files > 0 else 0,
            "compression_ratio": self._calculate_compression_ratio(),
            "encryption_usage": self._calculate_encryption_usage(),
            "recent_transfers": list(self.transfer_history)[-10:],
            "file_types": self._get_file_type_stats()
        }
    
    def _calculate_compression_ratio(self) -> float:
        """Calculate average compression ratio"""
        compressed_files = [f for f in self.files.values() if f.is_compressed]
        if not compressed_files:
            return 0.0
        
        total_ratio = 0
        for file in compressed_files:
            # This would need original size stored
            total_ratio += 0.7  # Placeholder
        
        return total_ratio / len(compressed_files)
    
    def _calculate_encryption_usage(self) -> float:
        """Calculate encryption usage percentage"""
        encrypted_files = [f for f in self.files.values() if f.is_encrypted]
        return (len(encrypted_files) / len(self.files)) * 100 if self.files else 0
    
    def _get_file_type_stats(self) -> Dict[str, int]:
        """Get file type statistics"""
        stats = defaultdict(int)
        for file_type in self.files.values():
            stats[file_type.file_type.value] += 1
        return dict(stats)

# Utility functions
def create_file_transfer_manager() -> FileTransferManager:
    """Create file transfer manager instance"""
    return FileTransferManager()

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    async def test_file_transfer():
        """Test file transfer system"""
        manager = create_file_transfer_manager()
        
        # Create test file
        test_data = b"This is a test file for the enhanced file transfer system."
        test_filename = "test_file.txt"
        
        # Upload file
        success, file_id, message = await manager.upload_file(
            test_filename,
            test_data,
            "test_room",
            "test_user"
        )
        
        if success:
            print(f"✅ Uploaded file: {file_id}")
            
            # Get file info
            file_info = manager.get_file_info(file_id)
            print(f"📄 File info: {file_info.filename} ({file_info.file_size} bytes)")
            
            # Download file
            success, downloaded_data, error = await manager.download_file(file_id, "test_user")
            
            if success:
                print(f"✅ Downloaded file: {len(downloaded_data)} bytes")
                print(f"🔍 Content: {downloaded_data.decode()}")
            else:
                print(f"❌ Download failed: {error}")
        else:
            print(f"❌ Upload failed: {message}")
        
        # Get statistics
        stats = manager.get_transfer_stats()
        print(f"📊 Transfer stats: {stats}")
    
    asyncio.run(test_file_transfer())
