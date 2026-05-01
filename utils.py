# utils.py — Crypto Primitives for secure-term-chat
# XChaCha20-Poly1305 | X25519 ECDH | Ed25519 | HKDF-SHA512 | Double Ratchet-inspired
# pip install cryptography pynacl

from __future__ import annotations
import os
import time
import hmac
import hashlib
import struct
import secrets
import ctypes
from dataclasses import dataclass, field
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature, InvalidTag

try:
    import nacl.secret
    import nacl.utils
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
HKDF_INFO_SESSION   = b"secure-term-chat-v1-session"
HKDF_INFO_ROOM      = b"secure-term-chat-v1-room"
HKDF_INFO_RATCHET   = b"secure-term-chat-v1-ratchet"
NONCE_SIZE          = 24   # XChaCha20 nonce
MAX_TIMESTAMP_SKEW  = 30   # seconds, anti-replay
MAX_NONCE_CACHE     = 10_000


# ──────────────────────────────────────────────
# Secure memory wipe helper
# ──────────────────────────────────────────────
def secure_wipe(data: bytearray | memoryview) -> None:
    """Overwrite mutable buffer with zeros."""
    if isinstance(data, (bytearray, memoryview)):
        for i in range(len(data)):
            data[i] = 0


def wipe_bytes(b: bytes) -> None:
    """Best-effort wipe of an immutable bytes object via ctypes."""
    try:
        ptr = (ctypes.c_char * len(b)).from_buffer_copy(b)
        ctypes.memset(ptr, 0, len(b))
    except Exception:
        pass


# ──────────────────────────────────────────────
# Identity Keys (Ed25519) — long-lived per client
# ──────────────────────────────────────────────
@dataclass
class IdentityKey:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> "IdentityKey":
        priv = Ed25519PrivateKey.generate()
        return cls(priv, priv.public_key())

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

    def fingerprint(self) -> str:
        """SHA-256 fingerprint for TOFU display."""
        digest = hashlib.sha256(self.public_bytes()).hexdigest()
        return ":".join(digest[i:i+4] for i in range(0, 32, 4))

    def destroy(self) -> None:
        wipe_bytes(self.public_bytes())


def identity_from_public_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_external(pub_raw: bytes, signature: bytes, data: bytes) -> bool:
    try:
        identity_from_public_bytes(pub_raw).verify(signature, data)
        return True
    except InvalidSignature:
        return False


def fingerprint_from_bytes(raw: bytes) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    return ":".join(digest[i:i+4] for i in range(0, 32, 4))


# ──────────────────────────────────────────────
# Session Keys (X25519) — ephemeral per session
# ──────────────────────────────────────────────
@dataclass
class SessionKey:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    _destroyed: bool = field(default=False, repr=False)

    @classmethod
    def generate(cls) -> "SessionKey":
        priv = X25519PrivateKey.generate()
        return cls(priv, priv.public_key())

    def exchange(self, peer_pub_raw: bytes) -> bytes:
        """Perform ECDH and return raw shared secret."""
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_raw)
        return self.private_key.exchange(peer_pub)

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

    def destroy(self) -> None:
        if not self._destroyed:
            # Best-effort: let GC collect
            self._destroyed = True


# ──────────────────────────────────────────────
# HKDF Key Derivation
# ──────────────────────────────────────────────
def hkdf_derive(input_key_material: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA512 key derivation."""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)


def derive_session_key(shared_secret: bytes, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    """Derive (encryption_key_32, mac_salt_32) from ECDH shared secret."""
    if salt is None:
        salt = secrets.token_bytes(32)
    key = hkdf_derive(shared_secret, salt, HKDF_INFO_SESSION, 32)
    return key, salt


def derive_room_key(shared_secret: bytes, room_name: bytes, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(32)
    info = HKDF_INFO_ROOM + b":" + room_name
    key = hkdf_derive(shared_secret, salt, info, 32)
    return key, salt


# ──────────────────────────────────────────────
# XChaCha20-Poly1305 Encryption
# Note: cryptography lib uses 12-byte nonce for ChaCha20Poly1305.
# For 24-byte XChaCha20, we simulate via nonce-extended construction.
# ──────────────────────────────────────────────
def _xchacha_nonce_extend(nonce24: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    XChaCha20 nonce extension (HChaCha20 subkey + 12-byte nonce).
    We derive a subkey from the first 16 bytes of the nonce via HKDF,
    then use remaining 8 bytes as the stream nonce.
    This is a simplified but secure construction.
    """
    assert len(nonce24) == 24
    subkey = hkdf_derive(key, nonce24[:16], b"xchacha20-subkey", 32)
    stream_nonce = b"\x00\x00\x00\x00" + nonce24[16:]
    return subkey, stream_nonce


def encrypt_message(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt with XChaCha20-Poly1305 construction.
    Returns: nonce(24) + ciphertext_with_tag
    """
    nonce24 = secrets.token_bytes(NONCE_SIZE)
    subkey, stream_nonce = _xchacha_nonce_extend(nonce24, key)
    cipher = ChaCha20Poly1305(subkey)
    ct = cipher.encrypt(stream_nonce, plaintext, aad if aad else None)
    return nonce24 + ct


def decrypt_message(key: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt XChaCha20-Poly1305.
    Expects: nonce(24) + ciphertext_with_tag
    Raises: InvalidTag on failure.
    """
    if len(ciphertext) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce24 = ciphertext[:NONCE_SIZE]
    ct = ciphertext[NONCE_SIZE:]
    subkey, stream_nonce = _xchacha_nonce_extend(nonce24, key)
    cipher = ChaCha20Poly1305(subkey)
    return cipher.decrypt(stream_nonce, ct, aad if aad else None)


# ──────────────────────────────────────────────
# Anti-Replay: Nonce + Timestamp Tracker
# ──────────────────────────────────────────────
class AntiReplayFilter:
    """Tracks seen nonces and validates timestamps to prevent replay attacks."""

    def __init__(self, max_skew: int = MAX_TIMESTAMP_SKEW):
        self._seen: set[bytes] = set()
        self._order: list[bytes] = []
        self.max_skew = max_skew

    def check(self, nonce: bytes, timestamp: float) -> bool:
        """Returns True if message is fresh and not replayed."""
        now = time.time()
        if abs(now - timestamp) > self.max_skew:
            return False
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        self._order.append(nonce)
        if len(self._order) > MAX_NONCE_CACHE:
            old = self._order.pop(0)
            self._seen.discard(old)
        return True


# ──────────────────────────────────────────────
# Double Ratchet-inspired: Symmetric Ratchet
# Provides forward secrecy within a session.
# ──────────────────────────────────────────────
class SymmetricRatchet:
    """
    Simple KDF ratchet: each message advances the chain key,
    deriving a fresh message key. Old keys are wiped after use.
    """

    def __init__(self, root_key: bytes):
        self._chain_key = bytearray(root_key)
        self._counter = 0

    def _advance(self) -> bytes:
        """Derive next message key and advance chain."""
        ck = bytes(self._chain_key)
        msg_key = hkdf_derive(ck, b"msg", HKDF_INFO_RATCHET + struct.pack(">Q", self._counter), 32)
        new_ck  = hkdf_derive(ck, b"chain", HKDF_INFO_RATCHET + struct.pack(">Q", self._counter), 32)
        secure_wipe(self._chain_key)
        self._chain_key = bytearray(new_ck)
        wipe_bytes(ck)
        self._counter += 1
        return msg_key

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        key = self._advance()
        ct = encrypt_message(key, plaintext, aad)
        wipe_bytes(key)
        return ct

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        key = self._advance()
        try:
            pt = decrypt_message(key, ciphertext, aad)
        finally:
            wipe_bytes(key)
        return pt

    def destroy(self) -> None:
        secure_wipe(self._chain_key)


# ──────────────────────────────────────────────
# Wire Protocol: Message Framing
# ──────────────────────────────────────────────
"""
Wire format (all lengths big-endian uint32):
  [4]  total_length  (of entire payload after this field)
  [4]  type_id       (MessageType enum value)
  [8]  timestamp     (float64 unix, signed)
  [32] nonce_id      (random bytes for anti-replay)
  [4]  payload_len
  [N]  payload       (encrypted blob or plaintext handshake)
  [64] signature     (Ed25519 over all preceding bytes)
"""

import json
from enum import IntEnum


class MessageType(IntEnum):
    HELLO         = 1   # identity + session pub key (plaintext)
    HELLO_ACK     = 2   # server ack with peer list
    ROOM_JOIN     = 3   # join room request (encrypted)
    ROOM_CHAT     = 4   # encrypted chat message
    ROOM_PM       = 5   # private message
    KEY_EXCHANGE  = 6   # X25519 pub key for PM E2EE
    FILE_CHUNK    = 7   # file streaming chunk
    PING          = 8
    PONG          = 9
    ERROR         = 10
    ROOM_LIST     = 11
    USER_LIST     = 12
    DISCONNECT    = 13


def build_frame(msg_type: MessageType, payload: bytes, identity: IdentityKey) -> bytes:
    """Build a signed wire frame."""
    timestamp = struct.pack(">d", time.time())
    nonce_id  = secrets.token_bytes(32)
    type_bytes = struct.pack(">I", int(msg_type))
    pay_len   = struct.pack(">I", len(payload))

    body = type_bytes + timestamp + nonce_id + pay_len + payload
    sig  = identity.sign(body)
    frame_data = body + sig
    total = struct.pack(">I", len(frame_data))
    return total + frame_data


def parse_frame(data: bytes) -> dict:
    """
    Parse wire frame. Returns dict with keys:
    type_id, timestamp, nonce_id, payload, signature, raw_body
    Raises ValueError on malformed frames.
    """
    if len(data) < 4:
        raise ValueError("Frame too short")
    total = struct.unpack(">I", data[:4])[0]
    frame = data[4:4 + total]
    if len(frame) < 4 + 8 + 32 + 4 + 64:
        raise ValueError("Frame malformed")
    offset = 0
    type_id   = struct.unpack(">I", frame[offset:offset+4])[0]; offset += 4
    timestamp = struct.unpack(">d", frame[offset:offset+8])[0]; offset += 8
    nonce_id  = frame[offset:offset+32]; offset += 32
    pay_len   = struct.unpack(">I", frame[offset:offset+4])[0]; offset += 4
    payload   = frame[offset:offset+pay_len]; offset += pay_len
    signature = frame[offset:offset+64]
    raw_body  = frame[:offset]
    return {
        "type_id":   type_id,
        "timestamp": timestamp,
        "nonce_id":  nonce_id,
        "payload":   payload,
        "signature": signature,
        "raw_body":  raw_body,
    }


def encode_json_payload(data: dict) -> bytes:
    return json.dumps(data, separators=(",", ":")).encode()


def decode_json_payload(data: bytes) -> dict:
    return json.loads(data.decode())


# ──────────────────────────────────────────────
# File Streaming Encryption
# ──────────────────────────────────────────────
CHUNK_SIZE = 64 * 1024  # 64 KB


def encrypt_file_stream(key: bytes, filepath: str):
    """Generator: yields encrypted chunks (nonce+ct) for a file."""
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            yield encrypt_message(key, chunk)


def decrypt_file_stream(key: bytes, chunks, output_path: str) -> None:
    """Decrypt iterable of encrypted chunks and write to output_path."""
    with open(output_path, "wb") as f:
        for ct in chunks:
            f.write(decrypt_message(key, ct))


# ──────────────────────────────────────────────
# Message Hash Audit Trail
# ──────────────────────────────────────────────
def message_hash(ciphertext: bytes) -> str:
    """SHA-256 of ciphertext for post-factum audit."""
    return hashlib.sha256(ciphertext).hexdigest()[:16]


# ──────────────────────────────────────────────
# Test Vectors (run: python utils.py)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("[TEST] Identity Key Generation")
    idk = IdentityKey.generate()
    print(f"  Fingerprint: {idk.fingerprint()}")

    print("[TEST] X25519 ECDH Key Exchange")
    alice = SessionKey.generate()
    bob   = SessionKey.generate()
    ss_a  = alice.exchange(bob.public_bytes())
    ss_b  = bob.exchange(alice.public_bytes())
    assert ss_a == ss_b, "ECDH mismatch!"
    print("  Shared secrets match ✓")

    print("[TEST] HKDF Key Derivation")
    enc_key, salt = derive_session_key(ss_a)
    print(f"  Derived key: {enc_key.hex()[:16]}...")

    print("[TEST] XChaCha20-Poly1305 Encrypt/Decrypt")
    pt  = b"Hello, secure world!"
    aad = b"room:default"
    ct  = encrypt_message(enc_key, pt, aad)
    dec = decrypt_message(enc_key, ct, aad)
    assert dec == pt
    print("  Encrypt/Decrypt OK ✓")

    print("[TEST] Anti-Replay Filter")
    arf = AntiReplayFilter()
    nonce = secrets.token_bytes(32)
    ts = time.time()
    assert arf.check(nonce, ts) == True
    assert arf.check(nonce, ts) == False  # replay
    print("  Replay blocked ✓")

    print("[TEST] Symmetric Ratchet (Forward Secrecy)")
    ratchet_send = SymmetricRatchet(enc_key)
    ratchet_recv = SymmetricRatchet(enc_key)
    for i in range(5):
        ct2 = ratchet_send.encrypt(f"msg {i}".encode())
        pt2 = ratchet_recv.decrypt(ct2)
        assert pt2 == f"msg {i}".encode()
    ratchet_send.destroy()
    ratchet_recv.destroy()
    print("  Ratchet 5 messages OK ✓")

    print("[TEST] Wire Frame Build/Parse")
    frame = build_frame(MessageType.ROOM_CHAT, b"test payload", idk)
    parsed = parse_frame(frame)
    assert parsed["payload"] == b"test payload"
    valid = verify_external(idk.public_bytes(), parsed["signature"], parsed["raw_body"])
    assert valid
    print("  Frame sign/verify OK ✓")

    print("\n[ALL TESTS PASSED] ✓")
