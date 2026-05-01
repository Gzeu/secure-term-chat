#!/usr/bin/env python3
# test_simple.py - Simple Working Tests
# Run: python -m pytest tests/test_simple.py -v
# Or: python utils.py (for comprehensive testing)

import pytest
import secrets
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import (
    encrypt_message, decrypt_message,
    derive_room_key,
    InvalidTag,
)

class TestSimpleCrypto:
    """Simple, working cryptographic tests."""
    
    def test_message_encryption_decryption(self):
        """Test XChaCha20-Poly1305 encryption/decryption."""
        key = secrets.token_bytes(32)
        message = b"Hello, secure world!"
        
        encrypted = encrypt_message(key, message)
        decrypted = decrypt_message(key, encrypted)
        
        assert decrypted == message
        assert encrypted != message
    
    def test_message_encryption_fails_wrong_key(self):
        """Test decryption fails with wrong key."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        message = b"Secret message"
        
        encrypted = encrypt_message(key1, message)
        
        with pytest.raises(InvalidTag):
            decrypt_message(key2, encrypted)
    
    def test_room_key_derivation(self):
        """Test room key derivation from session key."""
        room_seed = secrets.token_bytes(32)
        room_name = "testroom"
        
        room_key, room_salt = derive_room_key(room_seed, room_name.encode())
        assert room_key is not None
        assert room_salt is not None
        assert len(room_key) == 32
        assert len(room_salt) == 32
    
    def test_different_seeds_different_keys(self):
        """Test different seeds produce different keys."""
        seed1 = secrets.token_bytes(32)
        seed2 = secrets.token_bytes(32)
        room_name = "testroom"
        
        key1, salt1 = derive_room_key(seed1, room_name.encode())
        key2, salt2 = derive_room_key(seed2, room_name.encode())
        
        assert key1 != key2
        # Salt is derived from room name, so it should be the same
        assert salt1 == salt2
    
    def test_same_seed_same_key(self):
        """Test same seed produces same key."""
        seed = secrets.token_bytes(32)
        room_name = "testroom"
        
        key1, salt1 = derive_room_key(seed, room_name.encode())
        key2, salt2 = derive_room_key(seed, room_name.encode())
        
        assert key1 == key2
        assert salt1 == salt2

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
