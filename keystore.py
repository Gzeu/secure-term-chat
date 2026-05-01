#!/usr/bin/env python3
# keystore.py - Anonymous persistent identity keystore with Argon2id
# Stores identity keys securely with password-based encryption

from __future__ import annotations
import os
import json
import secrets
import struct
import time
from pathlib import Path
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

from utils import IdentityKey, wipe_bytearray


class AnonymousKeystore:
    """Anonymous persistent identity keystore with Argon2id protection."""
    
    def __init__(self, keystore_path: Optional[Path] = None):
        self.keystore_path = keystore_path or Path.home() / ".secure-term-chat" / "keystore.json"
        self.keystore_path.parent.mkdir(parents=True, exist_ok=True)
        self._identities: Dict[str, Dict] = {}
        self._master_key: Optional[bytes] = None
        self._unlocked = False
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using Argon2id."""
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,  # time_cost
            memory_cost=64 * 1024,  # 64MB
            lanes=4,  # parallelism -> lanes
        )
        return kdf.derive(password.encode())
    
    def _encrypt_data(self, data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data with ChaCha20Poly1305."""
        cipher = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)
        # ChaCha20Poly1305 returns ciphertext with tag appended
        tag = ciphertext[-16:]  # Last 16 bytes are the tag
        actual_ciphertext = ciphertext[:-16]
        return nonce, actual_ciphertext, tag
    
    def _decrypt_data(self, nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
        """Decrypt data with ChaCha20Poly1305."""
        cipher = ChaCha20Poly1305(key)
        # Combine ciphertext and tag for ChaCha20Poly1305
        encrypted_data = ciphertext + tag
        return cipher.decrypt(nonce, encrypted_data, None)
    
    def create_keystore(self, password: str) -> bool:
        """Create new keystore with password protection."""
        if self.keystore_path.exists():
            return False  # Keystore already exists
        
        # Generate master key
        master_salt = secrets.token_bytes(16)
        self._master_key = self._derive_key(password, master_salt)
        
        # Create empty keystore structure
        keystore_data = {
            "version": 1,
            "master_salt": master_salt.hex(),
            "identities": {}  # id -> encrypted identity data
        }
        
        # Save keystore
        self._save_keystore(keystore_data)
        self._unlocked = True
        return True
    
    def unlock(self, password: str) -> bool:
        """Unlock keystore with password."""
        if not self.keystore_path.exists():
            return False
        
        keystore_data = self._load_keystore()
        if not keystore_data:
            return False
        
        try:
            # Derive master key
            master_salt = bytes.fromhex(keystore_data["master_salt"])
            self._master_key = self._derive_key(password, master_salt)
            
            # Load identities
            self._identities = keystore_data.get("identities", {})
            self._unlocked = True
            return True
        except Exception:
            self._master_key = None
            self._unlocked = False
            return False
    
    def lock(self) -> None:
        """Lock keystore and wipe master key."""
        if self._master_key:
            wipe_bytearray(bytearray(self._master_key))
        self._master_key = None
        self._unlocked = False
        self._identities.clear()
    
    def is_unlocked(self) -> bool:
        """Check if keystore is unlocked."""
        return self._unlocked and self._master_key is not None
    
    def create_identity(self, name: str) -> Optional[IdentityKey]:
        """Create and store new anonymous identity."""
        if not self.is_unlocked():
            return None
        
        if name in self._identities:
            return None  # Identity already exists
        
        # Generate new identity
        identity = IdentityKey.generate()
        
        # Encrypt and store identity
        identity_data = {
            "private_key": identity.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).hex(),
            "created_at": int(time.time()),
        }
        
        serialized = json.dumps(identity_data).encode()
        nonce, ciphertext, tag = self._encrypt_data(serialized, self._master_key)
        
        self._identities[name] = {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex(),
        }
        
        # Save to disk
        self._save_keystore()
        return identity
    
    def get_identity(self, name: str) -> Optional[IdentityKey]:
        """Load identity from keystore."""
        if not self.is_unlocked() or name not in self._identities:
            return None
        
        try:
            stored = self._identities[name]
            nonce = bytes.fromhex(stored["nonce"])
            ciphertext = bytes.fromhex(stored["ciphertext"])
            tag = bytes.fromhex(stored["tag"])
            
            # Decrypt identity data
            decrypted = self._decrypt_data(nonce, ciphertext, tag, self._master_key)
            identity_data = json.loads(decrypted.decode())
            
            # Reconstruct identity
            private_key = serialization.load_pem_private_key(
                identity_data["private_key"].encode(),
                password=None,
            )
            
            return IdentityKey(private_key)
        except Exception:
            return None
    
    def list_identities(self) -> list[str]:
        """List all stored identity names."""
        if not self.is_unlocked():
            return []
        return list(self._identities.keys())
    
    def delete_identity(self, name: str) -> bool:
        """Delete identity from keystore."""
        if not self.is_unlocked() or name not in self._identities:
            return False
        
        del self._identities[name]
        self._save_keystore()
        return True
    
    def _load_keystore(self) -> Optional[Dict]:
        """Load keystore from disk."""
        try:
            with open(self.keystore_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def _save_keystore(self, extra_data: Optional[Dict] = None) -> None:
        """Save keystore to disk."""
        if not self.is_unlocked():
            return
        
        existing_keystore = self._load_keystore()
        master_salt = existing_keystore.get("master_salt", "") if existing_keystore else ""
        
        keystore_data = {
            "version": 1,
            "master_salt": master_salt,
            "identities": self._identities,
        }
        
        if extra_data:
            keystore_data.update(extra_data)
        
        with open(self.keystore_path, 'w') as f:
            json.dump(keystore_data, f, indent=2)
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change keystore password."""
        if not self.unlock(old_password):
            return False
        
        # Generate new master key
        new_master_salt = secrets.token_bytes(16)
        new_master_key = self._derive_key(new_password, new_master_salt)
        
        # Re-encrypt all identities with new key
        old_key = self._master_key
        self._master_key = new_master_key
        
        new_identities = {}
        for name, stored in self._identities.items():
            try:
                # Decrypt with old key
                nonce = bytes.fromhex(stored["nonce"])
                ciphertext = bytes.fromhex(stored["ciphertext"])
                tag = bytes.fromhex(stored["tag"])
                decrypted = self._decrypt_data(nonce, ciphertext, tag, old_key)
                
                # Re-encrypt with new key
                new_nonce, new_ciphertext, new_tag = self._encrypt_data(decrypted, new_master_key)
                
                new_identities[name] = {
                    "nonce": new_nonce.hex(),
                    "ciphertext": new_ciphertext.hex(),
                    "tag": new_tag.hex(),
                }
            except Exception:
                return False  # Failed to re-encrypt
        
        # Save with new master salt
        self._identities = new_identities
        self._save_keystore({"master_salt": new_master_salt.hex()})
        return True
    
    def __del__(self):
        """Cleanup on deletion."""
        self.lock()


def generate_temporary_nickname() -> str:
    """Generate a random temporary nickname for anonymous users."""
    adjectives = ["Happy", "Clever", "Swift", "Brave", "Quiet", "Bright", "Calm", "Bold"]
    nouns = ["Fox", "Wolf", "Eagle", "Bear", "Lion", "Hawk", "Owl", "Deer"]
    
    adjective = secrets.choice(adjectives)
    noun = secrets.choice(nouns)
    number = secrets.randbelow(1000)
    
    return f"{adjective}{noun}{number}"
