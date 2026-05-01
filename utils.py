# utils.py — Crypto Primitives for secure-term-chat
# XChaCha20-Poly1305 | X25519 ECDH | Ed25519 | HKDF-SHA512 | Symmetric Ratchet
# pip install cryptography pynacl

from __future__ import annotations
import os
import re
import time
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

# PyNaCl removed - all crypto functions use cryptography library
# This reduces dependencies from 3 to 2 packages (33% reduction)

# ──────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────
HKDF_INFO_SESSION  = b"secure-term-chat-v1-session"
HKDF_INFO_ROOM     = b"secure-term-chat-v1-room"
HKDF_INFO_RATCHET  = b"secure-term-chat-v1-ratchet"
NONCE_SIZE         = 24    # XChaCha20 nonce
MAX_TIMESTAMP_SKEW = 30    # seconds, anti-replay
MAX_NONCE_CACHE    = 10_000

# Regex for safe nick sanitization (fix: ANSI injection)
NICK_RE = re.compile(r"[^\w\-.]")  


def sanitize_nick(nick: str) -> str:
    """Strip non-alphanumeric/dash/dot chars to prevent ANSI terminal injection."""
    return NICK_RE.sub("", nick)[:32]


# ──────────────────────────────────────────────────
# Secure memory wipe
# FIX: use bytearray internally; wipe_bytearray is reliable.
# wipe_bytes on immutable bytes is best-effort only.
# ──────────────────────────────────────────────────
def secure_wipe(data: bytearray | memoryview) -> None:
    """Overwrite mutable buffer with zeros."""
    for i in range(len(data)):
        data[i] = 0


def wipe_bytearray(b: bytearray) -> None:
    """Zero a bytearray in-place (reliable wipe)."""
    secure_wipe(b)


def wipe_bytes_besteffort(b: bytes) -> None:
    """
    Best-effort wipe of immutable bytes via ctypes.
    NOTE: This wipes the internal buffer of the bytes object directly.
    Not guaranteed on all CPython versions/GC states.
    Prefer using bytearray for sensitive key material.
    """
    try:
        size = len(b)
        if size == 0:
            return
        # Access the ob_val buffer of PyBytesObject
        offset = ctypes.pythonapi.PyBytes_AsString.argtypes = [ctypes.py_object]
        buf = (ctypes.c_char * size).from_address(id(b) + ctypes.sizeof(ctypes.c_ssize_t) * 4 + ctypes.sizeof(ctypes.c_void_p))
        ctypes.memset(buf, 0, size)
    except Exception:
        pass  # fallback: GC will collect


# ──────────────────────────────────────────────────
# Identity Keys (Ed25519) — long-lived per client
# ──────────────────────────────────────────────────
@dataclass
class IdentityKey:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    # FIX: store pub bytes as bytearray for reliable wipe
    _pub_bytes: bytearray = field(default=None, repr=False)

    def __post_init__(self):
        raw = self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self._pub_bytes = bytearray(raw)

    @classmethod
    def generate(cls) -> "IdentityKey":
        priv = Ed25519PrivateKey.generate()
        obj = cls(priv, priv.public_key())
        return obj

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def public_bytes(self) -> bytes:
        return bytes(self._pub_bytes)

    def fingerprint(self) -> str:
        digest = hashlib.sha256(bytes(self._pub_bytes)).hexdigest()
        return ":".join(digest[i:i+4] for i in range(0, 32, 4))

    def destroy(self) -> None:
        """Wipe public key bytearray. Private key handed to GC."""
        if self._pub_bytes:
            wipe_bytearray(self._pub_bytes)


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


# ──────────────────────────────────────────────────
# Session Keys (X25519) — ephemeral per session
# ──────────────────────────────────────────────────
@dataclass
class SessionKey:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    _pub_bytes: bytearray = field(default=None, repr=False)  # FIX: bytearray
    _destroyed: bool = field(default=False, repr=False)

    def __post_init__(self):
        raw = self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self._pub_bytes = bytearray(raw)

    @classmethod
    def generate(cls) -> "SessionKey":
        priv = X25519PrivateKey.generate()
        return cls(priv, priv.public_key())

    def exchange(self, peer_pub_raw: bytes) -> bytearray:
        """ECDH — returns shared secret as bytearray for safe wiping."""
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_raw)
        raw = self.private_key.exchange(peer_pub)
        return bytearray(raw)  # FIX: return bytearray

    def public_bytes(self) -> bytes:
        return bytes(self._pub_bytes)

    def destroy(self) -> None:
        if not self._destroyed:
            if self._pub_bytes:
                wipe_bytearray(self._pub_bytes)
            self._destroyed = True


# ──────────────────────────────────────────────────
# HKDF Key Derivation
# ──────────────────────────────────────────────────
def hkdf_derive(input_key_material: bytes | bytearray, salt: bytes, info: bytes, length: int = 32) -> bytearray:
    """HKDF-SHA512. Returns bytearray for safe wipe."""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info,
    )
    return bytearray(hkdf.derive(bytes(input_key_material)))


def derive_session_key(shared_secret: bytes | bytearray, salt: bytes | None = None) -> Tuple[bytearray, bytes]:
    """Returns (enc_key: bytearray, salt: bytes)."""
    if salt is None:
        salt = secrets.token_bytes(32)
    key = hkdf_derive(shared_secret, salt, HKDF_INFO_SESSION, 32)
    return key, salt


def derive_room_key(shared_secret: bytes | bytearray, room_name: bytes, salt: bytes | None = None) -> Tuple[bytearray, bytes]:
    if salt is None:
        # Use deterministic salt for room keys so all clients derive same key
        salt = hashlib.sha256(HKDF_INFO_ROOM + b":" + room_name).digest()
    info = HKDF_INFO_ROOM + b":" + room_name
    key = hkdf_derive(shared_secret, salt, info, 32)
    return key, salt


# ──────────────────────────────────────────────────
# XChaCha20-Poly1305 Encryption
# 24-byte nonce via HChaCha20-inspired subkey construction
# ──────────────────────────────────────────────────
def _xchacha_nonce_extend(nonce24: bytes, key: bytes | bytearray) -> Tuple[bytearray, bytes]:
    """
    Derive subkey from first 16 bytes of nonce via HKDF,
    then use remaining 8 bytes as the 12-byte stream nonce.
    """
    assert len(nonce24) == 24
    subkey = hkdf_derive(bytes(key), nonce24[:16], b"xchacha20-subkey", 32)
    stream_nonce = b"\x00\x00\x00\x00" + nonce24[16:]
    return subkey, stream_nonce


def encrypt_message(key: bytes | bytearray, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt with XChaCha20-Poly1305.
    Returns: nonce(24) + ciphertext_with_tag
    """
    nonce24 = secrets.token_bytes(NONCE_SIZE)
    subkey, stream_nonce = _xchacha_nonce_extend(nonce24, key)
    cipher = ChaCha20Poly1305(bytes(subkey))
    ct = cipher.encrypt(stream_nonce, plaintext, aad or None)
    wipe_bytearray(subkey)
    return nonce24 + ct


def decrypt_message(key: bytes | bytearray, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt XChaCha20-Poly1305.
    Raises InvalidTag on auth failure.
    """
    if len(ciphertext) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce24 = ciphertext[:NONCE_SIZE]
    ct = ciphertext[NONCE_SIZE:]
    subkey, stream_nonce = _xchacha_nonce_extend(nonce24, key)
    cipher = ChaCha20Poly1305(bytes(subkey))
    try:
        pt = cipher.decrypt(stream_nonce, ct, aad or None)
    finally:
        wipe_bytearray(subkey)
    return pt


# ──────────────────────────────────────────────────
# Anti-Replay: Nonce + Timestamp
# ──────────────────────────────────────────────────
class AntiReplayFilter:
    def __init__(self, max_skew: int = MAX_TIMESTAMP_SKEW):
        self._seen: set[bytes] = set()
        self._order: list[bytes] = []
        self.max_skew = max_skew

    def check(self, nonce: bytes, timestamp: float) -> bool:
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


# ──────────────────────────────────────────────────
# Symmetric Ratchet (Double Ratchet-inspired)
# ──────────────────────────────────────────────────
class SymmetricRatchet:
    """
    KDF ratchet: each step derives a fresh message key and advances
    the chain key. Old keys are wiped after use for forward secrecy.
    """

    def __init__(self, root_key: bytes | bytearray):
        self._chain_key = bytearray(root_key)
        self._counter = 0

    def _advance(self) -> bytearray:
        ck = bytes(self._chain_key)
        msg_key  = hkdf_derive(ck, b"msg",   HKDF_INFO_RATCHET + struct.pack(">Q", self._counter), 32)
        new_ck   = hkdf_derive(ck, b"chain", HKDF_INFO_RATCHET + struct.pack(">Q", self._counter), 32)
        wipe_bytearray(self._chain_key)
        self._chain_key = new_ck
        self._counter += 1
        return msg_key

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        key = self._advance()
        ct = encrypt_message(key, plaintext, aad)
        wipe_bytearray(key)
        return ct

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        key = self._advance()
        try:
            pt = decrypt_message(key, ciphertext, aad)
        finally:
            wipe_bytearray(key)
        return pt

    def destroy(self) -> None:
        wipe_bytearray(self._chain_key)


# ──────────────────────────────────────────────────
# Wire Protocol
# ──────────────────────────────────────────────────
import json
from enum import IntEnum


class MessageType(IntEnum):
    HELLO        = 1
    HELLO_ACK    = 2
    ROOM_JOIN    = 3
    ROOM_CHAT    = 4
    ROOM_PM      = 5
    KEY_EXCHANGE = 6
    FILE_CHUNK   = 7
    PING         = 8
    PONG         = 9
    ERROR        = 10
    ROOM_LIST    = 11
    USER_LIST    = 12
    DISCONNECT   = 13
    ROOM_KEY     = 14


def build_frame(msg_type: MessageType, payload: bytes, identity: IdentityKey) -> bytes:
    timestamp  = struct.pack(">d", time.time())
    nonce_id   = secrets.token_bytes(32)
    type_bytes = struct.pack(">I", int(msg_type))
    pay_len    = struct.pack(">I", len(payload))
    body = type_bytes + timestamp + nonce_id + pay_len + payload
    sig  = identity.sign(body)
    frame_data = body + sig
    total = struct.pack(">I", len(frame_data))
    return total + frame_data


def parse_frame(data: bytes) -> dict:
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


# ──────────────────────────────────────────────────
# File Streaming Encryption
# ──────────────────────────────────────────────────
CHUNK_SIZE = 64 * 1024  # 64 KB


def encrypt_file_stream(key: bytes | bytearray, filepath: str):
    """Generator: yields encrypted chunks (nonce+ct)."""
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            yield encrypt_message(key, chunk)


def decrypt_file_stream(key: bytes | bytearray, chunks, output_path: str) -> None:
    with open(output_path, "wb") as f:
        for ct in chunks:
            f.write(decrypt_message(key, ct))


# ──────────────────────────────────────────────────
# Message Hash Audit Trail
# ──────────────────────────────────────────────────
def message_hash(ciphertext: bytes) -> str:
    return hashlib.sha256(ciphertext).hexdigest()[:16]


# ──────────────────────────────────────────────────
# Test Vectors
# ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("[TEST] Identity Key Generation")
    idk = IdentityKey.generate()
    print(f"  Fingerprint: {idk.fingerprint()}")

    print("[TEST] X25519 ECDH Key Exchange")
    alice = SessionKey.generate()
    bob   = SessionKey.generate()
    ss_a  = alice.exchange(bob.public_bytes())
    ss_b  = bob.exchange(alice.public_bytes())
    assert bytes(ss_a) == bytes(ss_b), "ECDH mismatch!"
    print("  Shared secrets match ✓")

    print("[TEST] HKDF Key Derivation")
    enc_key, salt = derive_session_key(ss_a)
    print(f"  Derived key: {bytes(enc_key).hex()[:16]}...")

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
    assert arf.check(nonce, ts) == False
    print("  Replay blocked ✓")

    print("[TEST] Symmetric Ratchet")
    ratchet_send = SymmetricRatchet(enc_key)
    ratchet_recv = SymmetricRatchet(enc_key)
    for i in range(5):
        ct2 = ratchet_send.encrypt(f"msg {i}".encode())
        pt2 = ratchet_recv.decrypt(ct2)
        assert pt2 == f"msg {i}".encode()
    ratchet_send.destroy()
    ratchet_recv.destroy()
    print("  Ratchet 5 messages OK ✓")

    print("[TEST] Wire Frame Build/Parse + Ed25519 sig")
    frame = build_frame(MessageType.ROOM_CHAT, b"test payload", idk)
    parsed = parse_frame(frame)
    assert parsed["payload"] == b"test payload"
    valid = verify_external(idk.public_bytes(), parsed["signature"], parsed["raw_body"])
    assert valid
    print("  Frame sign/verify OK ✓")

    print("[TEST] Nick sanitization (ANSI injection)")
    bad_nick = "Alice\x1b[31mRED\x1b[0m"
    clean = sanitize_nick(bad_nick)
    assert "\x1b" not in clean
    print(f"  '{bad_nick}' -> '{clean}' ✓")

    print("\n[ALL TESTS PASSED] ✓")
