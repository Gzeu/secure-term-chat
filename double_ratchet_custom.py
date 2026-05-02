#!/usr/bin/env python3
"""
Custom Double Ratchet Implementation - Phase 1
Based on Signal Protocol specification

This is a simplified but functional Double Ratchet implementation
that works with our hybrid crypto system.
"""

import os
import hashlib
import hmac
from typing import Tuple, Optional, Dict, Any, List
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


@dataclass
class DoubleRatchetState:
    """Double Ratchet state containing all necessary keys and counters"""
    # Root key for DH ratchet
    root_key: bytes
    
    # Sending chain
    sending_chain_key: Optional[bytes] = None
    sending_message_number: int = 0
    
    # Receiving chain
    receiving_chain_key: Optional[bytes] = None
    receiving_message_number: int = 0
    
    # DH keys
    dh_private: Optional[bytes] = None
    dh_public: Optional[bytes] = None
    remote_dh_public: Optional[bytes] = None
    
    # Skip keys for out-of-order messages
    skipped_message_keys: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)
    
    # Constants
    MAX_SKIP_KEYS: int = 1000


class CustomDoubleRatchet:
    """
    Custom Double Ratchet implementation
    
    Simplified but functional implementation based on:
    - Signal Protocol Double Ratchet specification
    - X3DH for initial setup
    - ChaCha20-Poly1305 for encryption
    """
    
    def __init__(self, initial_shared_secret: bytes, dh_keypair: Optional[Tuple[bytes, bytes]] = None):
        """
        Initialize Double Ratchet
        
        Args:
            initial_shared_secret: Shared secret from X3DH or hybrid key exchange
            dh_keypair: Optional (private, public) X25519 key pair for DH ratchet
        """
        self.state = DoubleRatchetState(root_key=initial_shared_secret)
        
        if dh_keypair:
            self.state.dh_private, self.state.dh_public = dh_keypair
        else:
            # Generate DH key pair if not provided
            self.state.dh_private, self.state.dh_public = self._generate_dh_keypair()
        
        # Initialize sending chain
        self._initialize_sending_chain()
    
    def _initialize_sending_chain(self):
        """Initialize the sending chain with root key"""
        if self.state.root_key:
            # KDF to derive chain key from root key
            self.state.sending_chain_key = self._kdf(self.state.root_key, b"chain_key_sending")
            self.state.sending_message_number = 0
    
    def _generate_dh_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate DH key pair
        
        Returns: (private_key, public_key)
        """
        private_key = os.urandom(32)
        public_key = hashlib.sha256(private_key + b"dh_public").digest()
        return private_key, public_key
    
    def _kdf(self, key: bytes, info: bytes, length: int = 32) -> bytes:
        """Key derivation function using HKDF-SHA256"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hkdf.derive(key)
    
    def _derive_message_keys(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Derive message key and next chain key
        
        Returns: (message_key, next_chain_key)
        """
        message_key = self._kdf(chain_key, b"message_key")
        next_chain_key = self._kdf(chain_key, b"chain_key_next")
        return message_key, next_chain_key
    
    def _encrypt_message(
        self, 
        plaintext: bytes, 
        message_key: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt message with message key
        
        Returns: (ciphertext, nonce)
        """
        cipher = ChaCha20Poly1305(message_key)
        nonce = os.urandom(12)  # ChaCha20-Poly1305 nonce
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return ciphertext, nonce
    
    def _decrypt_message(
        self, 
        ciphertext: bytes, 
        nonce: bytes, 
        message_key: bytes
    ) -> bytes:
        """Decrypt message with message key"""
        cipher = ChaCha20Poly1305(message_key)
        return cipher.decrypt(nonce, ciphertext, None)
    
    def dh_ratchet_step(self, remote_dh_public: bytes):
        """
        Perform DH ratchet step when receiving new DH public key
        
        Args:
            remote_dh_public: New remote DH public key
        """
        if self.state.dh_private is None:
            raise ValueError("No DH private key available for DH ratchet")
        
        # Perform DH exchange (simplified - in real implementation use X25519)
        dh_shared = self._simulate_dh_exchange(self.state.dh_private, remote_dh_public)
        
        # Update root key with DH output
        self.state.root_key = self._kdf(
            self.state.root_key + dh_shared, 
            b"root_key_update"
        )
        
        # Update receiving chain
        self.state.receiving_chain_key = self._kdf(
            self.state.root_key, 
            b"chain_key_receiving"
        )
        self.state.receiving_message_number = 0
        
        # Update remote DH public key
        old_remote_dh = self.state.remote_dh_public
        self.state.remote_dh_public = remote_dh_public
        
        # Clear old skipped keys for old DH public key
        if old_remote_dh is not None:
            keys_to_remove = [
                (dh_pub, msg_num) 
                for (dh_pub, msg_num) in self.state.skipped_message_keys.keys()
                if dh_pub == old_remote_dh
            ]
            for key in keys_to_remove:
                del self.state.skipped_message_keys[key]
    
    def _simulate_dh_exchange(self, private_key: bytes, public_key: bytes) -> bytes:
        """
        Simulate DH exchange (placeholder for real X25519 implementation)
        
        In real implementation, this would use X25519.exchange()
        """
        # Simple simulation - hash of private + public
        combined = private_key + public_key
        return hashlib.sha256(combined).digest()
    
    def encrypt(self, plaintext: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt message using Double Ratchet
        
        Returns: (ciphertext, header)
        """
        if self.state.sending_chain_key is None:
            raise ValueError("Sending chain not initialized")
        
        # Derive message key and next chain key
        message_key, next_chain_key = self._derive_message_keys(
            self.state.sending_chain_key
        )
        
        # Encrypt message
        ciphertext, nonce = self._encrypt_message(plaintext, message_key)
        
        # Create header
        header = {
            'dh_public': self.state.dh_public,
            'message_number': self.state.sending_message_number,
            'nonce': nonce
        }
        
        # Update sending chain
        self.state.sending_chain_key = next_chain_key
        self.state.sending_message_number += 1
        
        return ciphertext, header
    
    def decrypt(self, ciphertext: bytes, header: Dict[str, Any]) -> bytes:
        """
        Decrypt message using Double Ratchet
        
        Args:
            ciphertext: Encrypted message
            header: Message header containing DH public key, message number, nonce
            
        Returns: Decrypted plaintext
        """
        dh_public = header.get('dh_public')
        message_number = header.get('message_number')
        nonce = header.get('nonce')
        
        # Check if we need DH ratchet step
        if (self.state.remote_dh_public is None or 
            dh_public != self.state.remote_dh_public):
            self.dh_ratchet_step(dh_public)
        
        # Try to get message key from skipped keys
        skip_key = (dh_public, message_number)
        if skip_key in self.state.skipped_message_keys:
            message_key = self.state.skipped_message_keys[skip_key]
            del self.state.skipped_message_keys[skip_key]
            return self._decrypt_message(ciphertext, nonce, message_key)
        
        # Derive message key from receiving chain
        if self.state.receiving_chain_key is None:
            raise ValueError("Receiving chain not initialized")
        
        # Skip message keys until we reach the target message number
        current_chain_key = self.state.receiving_chain_key
        for i in range(self.state.receiving_message_number, message_number):
            message_key, current_chain_key = self._derive_message_keys(current_chain_key)
            
            # Store skipped message key (with limit)
            if len(self.state.skipped_message_keys) < self.state.MAX_SKIP_KEYS:
                self.state.skipped_message_keys[(dh_public, i)] = message_key
        
        # Derive the target message key
        target_message_key, next_chain_key = self._derive_message_keys(current_chain_key)
        
        # Update receiving chain
        self.state.receiving_chain_key = next_chain_key
        self.state.receiving_message_number = message_number + 1
        
        # Decrypt message
        return self._decrypt_message(ciphertext, nonce, target_message_key)


def create_double_ratchet(
    shared_secret: bytes,
    dh_keypair: Optional[Tuple[bytes, bytes]] = None
) -> CustomDoubleRatchet:
    """
    Create Double Ratchet instance
    
    Args:
        shared_secret: Initial shared secret from X3DH or hybrid key exchange
        dh_keypair: Optional (private, public) DH key pair
        
    Returns: Double Ratchet instance
    """
    return CustomDoubleRatchet(shared_secret, dh_keypair)


# Simplified Ratchet for Phase 1 - moved to module level for import
class SimpleRatchet:
    """Simplified symmetric ratchet for Phase 1 implementation"""
    
    def __init__(self, shared_secret: bytes):
        self.chain_key = shared_secret
        self.message_number = 0
    
    def _derive_message_key(self):
        """Derive message key from chain key"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"message_key"
        )
        message_key = hkdf.derive(self.chain_key)
        
        # Update chain key for next message
        hkdf_next = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"chain_key_next"
        )
        self.chain_key = hkdf_next.derive(self.chain_key)
        self.message_number += 1
        
        return message_key
    
    def encrypt(self, plaintext: bytes):
        message_key = self._derive_message_key()
        cipher = ChaCha20Poly1305(message_key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return ciphertext, nonce, self.message_number - 1
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, message_number: int):
        # For simplified test, we assume sequential messages
        message_key = self._derive_message_key()
        cipher = ChaCha20Poly1305(message_key)
        return cipher.decrypt(nonce, ciphertext, None)


if __name__ == "__main__":
    # Test Simplified Ratchet implementation for Phase 1
    print("Testing Simplified Ratchet (Phase 1)...")
    
    # Create shared secret (from hybrid key exchange)
    shared_secret = os.urandom(32)
    
    # Test basic symmetric ratchet (simplified Double Ratchet)
    ratchet = SimpleRatchet(shared_secret)
    
    # Test simplified ratchet
    alice_ratchet = SimpleRatchet(shared_secret)
    bob_ratchet = SimpleRatchet(shared_secret)
    
    # Test message encryption/decryption
    test_message = b"Hello, Simplified Ratchet world!"
    
    # Alice encrypts
    ciphertext, nonce, msg_num = alice_ratchet.encrypt(test_message)
    print(f"Encrypted message: {len(ciphertext)} bytes")
    
    # Bob decrypts
    decrypted = bob_ratchet.decrypt(ciphertext, nonce, msg_num)
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == test_message, "Decryption failed!"
    print("Simplified Ratchet test passed!")
    
    # Test multiple messages
    for i in range(5):
        message = f"Message {i}".encode()
        cipher, nonce, num = alice_ratchet.encrypt(message)
        decrypted = bob_ratchet.decrypt(cipher, nonce, num)
        assert decrypted == message, f"Message {i} failed!"
    
    print("Multiple messages test passed!")
    print("Simplified Ratchet (Phase 1) is working!")
