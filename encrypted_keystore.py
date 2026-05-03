#!/usr/bin/env python3
"""
Encrypted Keystore for secure-term-chat
Password-protected storage for identity keys and sensitive data
"""

import os
import json
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    import argon2
except ImportError:
    argon2 = None

try:
    from hybrid_crypto import IdentityKey
except ImportError:
    IdentityKey = None

@dataclass
class KeystoreEntry:
    """Single entry in encrypted keystore"""
    name: str
    encrypted_data: bytes
    salt: bytes
    iv: bytes
    algorithm: str = "AES-256-GCM"
    kdf: str = "PBKDF2"
    created_at: float = None
    last_accessed: float = None
    
    def __post_init__(self):
        import time
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_accessed is None:
            self.last_accessed = time.time()

class EncryptedKeystore:
    """Encrypted keystore for secure key storage"""
    
    def __init__(self, keystore_path: Path, password: str, kdf_algorithm: str = "argon2"):
        self.keystore_path = keystore_path
        self.password = password.encode('utf-8')
        self.kdf_algorithm = kdf_algorithm
        self.entries: Dict[str, KeystoreEntry] = {}
        self.master_key: Optional[bytes] = None
        self._load_keystore()
    
    def _derive_key(self, salt: bytes, kdf: str = None) -> bytes:
        """Derive encryption key from password"""
        kdf = kdf or self.kdf_algorithm
        
        if kdf == "argon2":
            # Use Argon2 for better security
            if argon2 is None:
                raise ImportError("argon2-cffi is required for Argon2 key derivation")
            argon2_hasher = argon2.PasswordHasher(
                time_cost=3,  # Number of iterations
                memory_cost=65536,  # Memory usage in KB
                parallelism=4,  # Number of parallel threads
                hash_len=32,  # Output hash length
                salt_len=16  # Salt length
            )
            return argon2_hasher.hash(self.password + salt)
        elif kdf == "bcrypt":
            # Use bcrypt as alternative
            if bcrypt is None:
                raise ImportError("bcrypt is required for bcrypt key derivation")
            salt_bytes = bcrypt.gensalt()
            hashed = bcrypt.hashpw(self.password + salt, salt_bytes)
            return hashed[:32]  # Take first 32 bytes as key
        else:
            # Default to PBKDF2
            kdf_obj = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,  # High iteration count for security
                backend=default_backend()
            )
            return kdf_obj.derive(self.password)
    
    def _encrypt_data(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM"""
        # Generate random IV
        iv = os.urandom(12)  # 96-bit IV for GCM
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + ciphertext + tag
        return iv + ciphertext + encryptor.tag, iv
    
    def _decrypt_data(self, encrypted_data: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        return decryptor.update(encrypted_data) + decryptor.finalize()
    
    def _generate_master_key(self) -> bytes:
        """Generate master key from password"""
        salt = os.urandom(32)
        return self._derive_key(salt), salt
    
    def _load_keystore(self) -> None:
        """Load existing keystore or create new one"""
        if self.keystore_path.exists():
            try:
                with open(self.keystore_path, 'rb') as f:
                    keystore_data = json.loads(f.read().decode('utf-8'))
                
                # Load master key
                master_entry = keystore_data.get('master_key')
                if master_entry:
                    salt = bytes.fromhex(master_entry['salt'])
                    self.master_key = self._derive_key(salt, master_entry.get('kdf', self.kdf_algorithm))
                
                # Load entries
                entries_data = keystore_data.get('entries', {})
                for name, entry_data in entries_data.items():
                    self.entries[name] = KeystoreEntry(
                        name=entry_data['name'],
                        encrypted_data=bytes.fromhex(entry_data['encrypted_data']),
                        salt=bytes.fromhex(entry_data['salt']),
                        iv=bytes.fromhex(entry_data['iv']),
                        algorithm=entry_data.get('algorithm', 'AES-256-GCM'),
                        kdf=entry_data.get('kdf', 'PBKDF2'),
                        created_at=entry_data.get('created_at'),
                        last_accessed=entry_data.get('last_accessed')
                    )
                
                print(f"✅ Keystore loaded from {self.keystore_path}")
                
            except Exception as e:
                print(f"❌ Error loading keystore: {e}")
                self._create_new_keystore()
        else:
            self._create_new_keystore()
    
    def _create_new_keystore(self) -> None:
        """Create new keystore"""
        # Generate master key
        self.master_key, salt = self._generate_master_key()
        
        # Create keystore directory if needed
        self.keystore_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save empty keystore
        self._save_keystore()
        
        print(f"✅ New keystore created at {self.keystore_path}")
    
    def _save_keystore(self) -> None:
        """Save keystore to file"""
        keystore_data = {
            'version': '1.0',
            'created_at': self.entries.get('master_key', {}).get('created_at', 0),
            'master_key': {
                'salt': self.keystore_path.name.encode('utf-8').hex() if self.master_key else '',
                'kdf': self.kdf_algorithm
            },
            'entries': {}
        }
        
        # Save entries
        for name, entry in self.entries.items():
            keystore_data['entries'][name] = {
                'name': entry.name,
                'encrypted_data': entry.encrypted_data.hex(),
                'salt': entry.salt.hex(),
                'iv': entry.iv.hex(),
                'algorithm': entry.algorithm,
                'kdf': entry.kdf,
                'created_at': entry.created_at,
                'last_accessed': entry.last_accessed
            }
        
        # Write to file
        with open(self.keystore_path, 'w') as f:
            json.dump(keystore_data, f, indent=2)
        
        print(f"💾 Keystore saved to {self.keystore_path}")
    
    def store_identity_key(self, identity, name: str = "default") -> bool:
        """Store identity key in keystore"""
        try:
            if IdentityKey is None:
                print("❌ hybrid_crypto module not available")
                return False
                
            if not self.master_key:
                print("❌ No master key available")
                return False
            
            # Serialize identity key
            identity_data = identity.serialize()
            
            # Encrypt with master key
            encrypted_data, iv = self._encrypt_data(identity_data, self.master_key)
            
            # Extract tag from GCM mode
            tag = encrypted_data[-16:]  # Last 16 bytes are the tag
            ciphertext = encrypted_data[:-16]  # Remove tag from ciphertext
            
            # Create entry
            salt = os.urandom(32)
            entry = KeystoreEntry(
                name=name,
                encrypted_data=ciphertext,
                salt=salt,
                iv=iv,
                created_at=identity_data.get('created_at'),
                last_accessed=identity_data.get('last_accessed')
            )
            
            # Store entry
            self.entries[name] = entry
            
            # Save keystore
            self._save_keystore()
            
            print(f"✅ Identity key '{name}' stored in keystore")
            return True
            
        except Exception as e:
            print(f"❌ Error storing identity key: {e}")
            return False
    
    def retrieve_identity_key(self, name: str = "default"):
        """Retrieve identity key from keystore"""
        try:
            if IdentityKey is None:
                print("❌ hybrid_crypto module not available")
                return None
                
            if name not in self.entries:
                print(f"❌ Identity key '{name}' not found in keystore")
                return None
            
            if not self.master_key:
                print("❌ No master key available")
                return None
            
            entry = self.entries[name]
            
            # Reconstruct encrypted data with tag
            encrypted_data = entry.encrypted_data + entry.iv[-16:]  # Add tag from IV
            
            # Decrypt with master key
            decrypted_data = self._decrypt_data(
                entry.encrypted_data,
                self.master_key,
                entry.iv,
                entry.iv[-16:]  # Tag is last 16 bytes of IV
            )
            
            # Deserialize identity key
            identity = IdentityKey.deserialize(decrypted_data)
            
            # Update last accessed
            entry.last_accessed = time.time()
            self._save_keystore()
            
            print(f"✅ Identity key '{name}' retrieved from keystore")
            return identity
            
        except Exception as e:
            print(f"❌ Error retrieving identity key: {e}")
            return None
    
    def store_data(self, data: Dict[str, Any], name: str) -> bool:
        """Store arbitrary data in keystore"""
        try:
            if not self.master_key:
                print("❌ No master key available")
                return False
            
            # Serialize data
            data_bytes = json.dumps(data).encode('utf-8')
            
            # Encrypt with master key
            encrypted_data, iv = self._encrypt_data(data_bytes, self.master_key)
            
            # Create entry
            salt = os.urandom(32)
            entry = KeystoreEntry(
                name=name,
                encrypted_data=encrypted_data,
                salt=salt,
                iv=iv
            )
            
            # Store entry
            self.entries[name] = entry
            
            # Save keystore
            self._save_keystore()
            
            print(f"✅ Data '{name}' stored in keystore")
            return True
            
        except Exception as e:
            print(f"❌ Error storing data: {e}")
            return False
    
    def retrieve_data(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve arbitrary data from keystore"""
        try:
            if name not in self.entries:
                print(f"❌ Data '{name}' not found in keystore")
                return None
            
            if not self.master_key:
                print("❌ No master key available")
                return None
            
            entry = self.entries[name]
            
            # Decrypt with master key
            decrypted_data = self._decrypt_data(
                entry.encrypted_data,
                self.master_key,
                entry.iv,
                entry.iv[-16:]  # Tag is last 16 bytes of IV
            )
            
            # Deserialize data
            data = json.loads(decrypted_data.decode('utf-8'))
            
            # Update last accessed
            entry.last_accessed = time.time()
            self._save_keystore()
            
            print(f"✅ Data '{name}' retrieved from keystore")
            return data
            
        except Exception as e:
            print(f"❌ Error retrieving data: {e}")
            return None
    
    def list_entries(self) -> List[str]:
        """List all entries in keystore"""
        return list(self.entries.keys())
    
    def delete_entry(self, name: str) -> bool:
        """Delete entry from keystore"""
        try:
            if name in self.entries:
                del self.entries[name]
                self._save_keystore()
                print(f"✅ Entry '{name}' deleted from keystore")
                return True
            else:
                print(f"❌ Entry '{name}' not found in keystore")
                return False
        except Exception as e:
            print(f"❌ Error deleting entry: {e}")
            return False
    
    def change_password(self, new_password: str) -> bool:
        """Change keystore password"""
        try:
            # Generate new master key
            new_password_bytes = new_password.encode('utf-8')
            salt = os.urandom(32)
            
            if self.kdf_algorithm == "argon2":
                if argon2 is None:
                    raise ImportError("argon2-cffi is required for Argon2 key derivation")
                argon2_hasher = argon2.PasswordHasher(
                    time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
                )
                new_master_key = argon2_hasher.hash(new_password_bytes + salt)
            elif self.kdf_algorithm == "bcrypt":
                if bcrypt is None:
                    raise ImportError("bcrypt is required for bcrypt key derivation")
                salt_bytes = bcrypt.gensalt()
                hashed = bcrypt.hashpw(new_password_bytes + salt, salt_bytes)
                new_master_key = hashed[:32]
            else:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
                )
                new_master_key = kdf.derive(new_password_bytes)
            
            # Re-encrypt all entries with new master key
            for name, entry in self.entries.items():
                # Decrypt with old key
                decrypted_data = self._decrypt_data(
                    entry.encrypted_data,
                    self.master_key,
                    entry.iv,
                    entry.iv[-16:]
                )
                
                # Encrypt with new key
                new_encrypted_data, new_iv = self._encrypt_data(decrypted_data, new_master_key)
                
                # Update entry
                entry.encrypted_data = new_encrypted_data
                entry.iv = new_iv
                entry.salt = salt
            
            # Update master key
            self.master_key = new_master_key
            self.password = new_password_bytes
            
            # Save keystore
            self._save_keystore()
            
            print(f"✅ Keystore password changed successfully")
            return True
            
        except Exception as e:
            print(f"❌ Error changing password: {e}")
            return False
    
    def backup_keystore(self, backup_path: Path) -> bool:
        """Create backup of keystore"""
        try:
            import shutil
            shutil.copy2(self.keystore_path, backup_path)
            print(f"✅ Keystore backed up to {backup_path}")
            return True
        except Exception as e:
            print(f"❌ Error creating backup: {e}")
            return False
    
    def restore_keystore(self, backup_path: Path) -> bool:
        """Restore keystore from backup"""
        try:
            import shutil
            shutil.copy2(backup_path, self.keystore_path)
            self._load_keystore()
            print(f"✅ Keystore restored from {backup_path}")
            return True
        except Exception as e:
            print(f"❌ Error restoring keystore: {e}")
            return False
    
    def get_keystore_info(self) -> Dict[str, Any]:
        """Get keystore information"""
        return {
            'path': str(self.keystore_path),
            'entries_count': len(self.entries),
            'entries': list(self.entries.keys()),
            'kdf_algorithm': self.kdf_algorithm,
            'has_master_key': self.master_key is not None,
            'created_at': self.entries.get('master_key', {}).get('created_at'),
            'last_accessed': max([e.last_accessed for e in self.entries.values()], default=0)
        }

# Utility functions
def create_keystore(keystore_dir: Path, password: str, kdf: str = "argon2") -> EncryptedKeystore:
    """Create new keystore"""
    keystore_path = keystore_dir / "secure_keystore.json"
    return EncryptedKeystore(keystore_path, password, kdf)

def load_keystore(keystore_dir: Path, password: str, kdf: str = "argon2") -> Optional[EncryptedKeystore]:
    """Load existing keystore"""
    keystore_path = keystore_dir / "secure_keystore.json"
    if keystore_path.exists():
        return EncryptedKeystore(keystore_path, password, kdf)
    return None

def verify_keystore_password(keystore_dir: Path, password: str) -> bool:
    """Verify keystore password"""
    try:
        keystore_path = keystore_dir / "secure_keystore.json"
        if not keystore_path.exists():
            return False
        
        keystore = EncryptedKeystore(keystore_path, password)
        return keystore.master_key is not None
    except:
        return False

# Main usage example
if __name__ == "__main__":
    import time
    from pathlib import Path
    
    # Test keystore
    keystore_dir = Path.home() / ".secure-term-chat"
    password = "test_password_123"
    
    # Create keystore
    keystore = create_keystore(keystore_dir, password, "argon2")
    
    # Test data storage
    test_data = {
        "test": "data",
        "timestamp": time.time(),
        "sensitive": "information"
    }
    
    # Store data
    keystore.store_data(test_data, "test_entry")
    
    # Retrieve data
    retrieved_data = keystore.retrieve_data("test_entry")
    print(f"Retrieved data: {retrieved_data}")
    
    # List entries
    print(f"Entries: {keystore.list_entries()}")
    
    # Get keystore info
    print(f"Keystore info: {keystore.get_keystore_info()}")
