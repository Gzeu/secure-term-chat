#!/usr/bin/env python3
"""
Advanced Performance and Security Optimizations for secure-term-chat
- Cryptographic operation caching
- Memory pool optimization
- Connection state management
- Adaptive compression
- Zero-copy operations
"""

import asyncio
import time
import hashlib
import struct
import secrets
from collections import OrderedDict, deque
from typing import Dict, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from functools import lru_cache
import weakref

# ──────────────────────────────────────────────────
# Cryptographic Operation Caching
# ──────────────────────────────────────────────────
class CryptoCache:
    """LRU cache for expensive cryptographic operations"""
    
    def __init__(self, max_size: int = 1000):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[bytes]:
        """Get cached cryptographic result"""
        if key in self._cache:
            # Move to end (LRU)
            value = self._cache.pop(key)
            self._cache[key] = value
            self._hits += 1
            return value
        self._misses += 1
        return None
    
    def put(self, key: str, value: bytes) -> None:
        """Cache cryptographic result"""
        if len(self._cache) >= self._max_size:
            # Remove oldest (LRU)
            self._cache.popitem(last=False)
        self._cache[key] = value
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%"
        }

# Global crypto cache
CRYPTO_CACHE = CryptoCache()

# ──────────────────────────────────────────────────
# Memory Pool Manager
# ──────────────────────────────────────────────────
@dataclass
class MemoryBlock:
    """Memory block with metadata"""
    data: bytearray
    size: int
    allocated_at: float
    last_used: float = field(default_factory=time.time)
    
    def touch(self) -> None:
        """Update last used time"""
        self.last_used = time.time()

class AdvancedMemoryPool:
    """Advanced memory pool with size-based management"""
    
    def __init__(self, max_memory: int = 100 * 1024 * 1024):  # 100MB default
        self._pools: Dict[int, deque] = {}  # size -> deque of blocks
        self._total_allocated = 0
        self._max_memory = max_memory
        self._stats = {
            "allocations": 0,
            "deallocations": 0,
            "reuses": 0,
            "peak_memory": 0
        }
    
    def get_block(self, size: int) -> MemoryBlock:
        """Get memory block of at least specified size"""
        # Round up to nearest power of 2 for better reuse
        rounded_size = 1 << (size - 1).bit_length()
        
        if rounded_size not in self._pools:
            self._pools[rounded_size] = deque()
        
        pool = self._pools[rounded_size]
        
        if pool:
            block = pool.popleft()
            block.touch()
            self._stats["reuses"] += 1
            return block
        else:
            # Allocate new block
            block = MemoryBlock(
                data=bytearray(rounded_size),
                size=rounded_size,
                allocated_at=time.time()
            )
            self._total_allocated += rounded_size
            self._stats["allocations"] += 1
            self._stats["peak_memory"] = max(self._stats["peak_memory"], self._total_allocated)
            return block
    
    def return_block(self, block: MemoryBlock) -> None:
        """Return block to pool after secure wiping"""
        # Secure wipe
        memoryview(block.data)[:] = b'\x00' * len(block.data)
        
        pool = self._pools.get(block.size)
        if pool is not None and len(pool) < 10:  # Limit pool size per size
            pool.append(block)
            self._stats["deallocations"] += 1
        else:
            # Let GC handle it
            self._total_allocated -= block.size
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory pool statistics"""
        return {
            **self._stats,
            "current_memory": self._total_allocated,
            "max_memory": self._max_memory,
            "utilization": f"{(self._total_allocated / self._max_memory * 100):.1f}%",
            "pools": {size: len(pool) for size, pool in self._pools.items()}
        }

# Global advanced memory pool
ADVANCED_MEMORY_POOL = AdvancedMemoryPool()

# ──────────────────────────────────────────────────
# Adaptive Compression
# ──────────────────────────────────────────────────
class AdaptiveCompressor:
    """Adaptive compression with dynamic threshold adjustment"""
    
    def __init__(self):
        self._compression_stats = {
            "total_compressed": 0,
            "total_original": 0,
            "compression_ratio": 0.0,
            "threshold": 1024,  # Start with 1KB
            "adjustment_interval": 100,
            "samples": 0
        }
    
    def compress(self, data: bytes) -> Tuple[bytes, bool]:
        """Compress data with adaptive threshold"""
        import zlib
        
        if len(data) < self._compression_stats["threshold"]:
            return data, False
        
        compressed = zlib.compress(data, level=6)
        
        # Update statistics
        self._compression_stats["samples"] += 1
        self._compression_stats["total_original"] += len(data)
        
        if len(compressed) < len(data) * 0.9:  # At least 10% reduction
            self._compression_stats["total_compressed"] += len(compressed)
            return b'\x01' + compressed, True
        else:
            return b'\x00' + data, False
    
    def decompress(self, data: bytes) -> bytes:
        """Decompress data"""
        import zlib
        
        if len(data) < 1:
            return data
        
        flag = data[0]
        payload = data[1:]
        
        if flag == 0x01:
            try:
                return zlib.decompress(payload)
            except zlib.error:
                return payload
        elif flag == 0x00:
            return payload
        else:
            return data
    
    def _adjust_threshold(self) -> None:
        """Adjust compression threshold based on performance"""
        if self._compression_stats["samples"] < self._compression_stats["adjustment_interval"]:
            return
        
        if self._compression_stats["total_original"] > 0:
            ratio = self._compression_stats["total_compressed"] / self._compression_stats["total_original"]
            
            # Adjust threshold based on compression effectiveness
            if ratio < 0.5:  # Good compression
                self._compression_stats["threshold"] = max(512, self._compression_stats["threshold"] - 128)
            elif ratio > 0.8:  # Poor compression
                self._compression_stats["threshold"] = min(4096, self._compression_stats["threshold"] + 128)
            
            # Reset statistics
            self._compression_stats["total_compressed"] = 0
            self._compression_stats["total_original"] = 0
            self._compression_stats["samples"] = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get compression statistics"""
        self._adjust_threshold()
        return {
            "threshold": self._compression_stats["threshold"],
            "samples": self._compression_stats["samples"],
            "current_ratio": self._compression_stats.get("compression_ratio", 0.0)
        }

# Global adaptive compressor
ADAPTIVE_COMPRESSOR = AdaptiveCompressor()

# ──────────────────────────────────────────────────
# Zero-Copy Operations
# ──────────────────────────────────────────────────
class ZeroCopyBuffer:
    """Zero-copy buffer for network operations"""
    
    def __init__(self, initial_size: int = 64 * 1024):
        self._buffer = bytearray(initial_size)
        self._write_pos = 0
        self._read_pos = 0
        self._views: weakref.WeakSet = weakref.WeakSet()
    
    def write(self, data: bytes) -> None:
        """Write data to buffer"""
        required = self._write_pos + len(data)
        if required > len(self._buffer):
            # Expand buffer
            new_size = max(required, len(self._buffer) * 2)
            new_buffer = bytearray(new_size)
            new_buffer[:self._write_pos] = self._buffer[:self._write_pos]
            self._buffer = new_buffer
        
        self._buffer[self._write_pos:self._write_pos + len(data)] = data
        self._write_pos += len(data)
    
    def read(self, size: int) -> memoryview:
        """Read data as memoryview (zero-copy)"""
        available = min(size, self._write_pos - self._read_pos)
        view = memoryview(self._buffer)[self._read_pos:self._read_pos + available]
        self._read_pos += available
        
        # Compact if we've read most of the buffer
        if self._read_pos > len(self._buffer) // 2:
            remaining = self._write_pos - self._read_pos
            if remaining > 0:
                self._buffer[:remaining] = self._buffer[self._read_pos:self._write_pos]
            self._write_pos = remaining
            self._read_pos = 0
        
        return view
    
    def flush(self) -> None:
        """Reset buffer"""
        self._write_pos = 0
        self._read_pos = 0
        memoryview(self._buffer)[:] = b'\x00' * len(self._buffer)

# ──────────────────────────────────────────────────
# Connection State Manager
# ──────────────────────────────────────────────────
@dataclass
class ConnectionState:
    """Optimized connection state management"""
    peer_id: str
    last_activity: float = field(default_factory=time.time)
    message_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    compression_enabled: bool = True
    crypto_cache_hits: int = 0
    crypto_cache_misses: int = 0
    
    def update_activity(self) -> None:
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        cache_total = self.crypto_cache_hits + self.crypto_cache_misses
        cache_hit_rate = (self.crypto_cache_hits / cache_total * 100) if cache_total > 0 else 0
        return {
            "peer_id": self.peer_id,
            "last_activity": self.last_activity,
            "message_count": self.message_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "compression_enabled": self.compression_enabled,
            "crypto_cache_hit_rate": f"{cache_hit_rate:.1f}%"
        }

class ConnectionManager:
    """Manages multiple connection states efficiently"""
    
    def __init__(self, cleanup_interval: float = 60.0):
        self._connections: Dict[str, ConnectionState] = {}
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()
    
    def get_connection(self, peer_id: str) -> ConnectionState:
        """Get or create connection state"""
        if peer_id not in self._connections:
            self._connections[peer_id] = ConnectionState(peer_id=peer_id)
        return self._connections[peer_id]
    
    def remove_connection(self, peer_id: str) -> Optional[ConnectionState]:
        """Remove connection and return its state"""
        return self._connections.pop(peer_id, None)
    
    def cleanup_stale(self, timeout: float = 300.0) -> int:
        """Remove stale connections and return count"""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return 0
        
        stale_peers = [
            peer_id for peer_id, state in self._connections.items()
            if now - state.last_activity > timeout
        ]
        
        for peer_id in stale_peers:
            self._connections.pop(peer_id, None)
        
        self._last_cleanup = now
        return len(stale_peers)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection manager statistics"""
        return {
            "active_connections": len(self._connections),
            "total_messages": sum(state.message_count for state in self._connections.values()),
            "total_bytes_sent": sum(state.bytes_sent for state in self._connections.values()),
            "total_bytes_received": sum(state.bytes_received for state in self._connections.values())
        }

# Global connection manager
CONNECTION_MANAGER = ConnectionManager()

# ──────────────────────────────────────────────────
# Performance Optimizer
# ──────────────────────────────────────────────────
class PerformanceOptimizer:
    """Main performance optimization coordinator"""
    
    def __init__(self):
        self.start_time = time.time()
        self.optimizations_enabled = {
            "crypto_cache": True,
            "advanced_memory_pool": True,
            "adaptive_compression": True,
            "zero_copy_buffers": True,
            "connection_management": True
        }
    
    def get_comprehensive_report(self) -> str:
        """Get comprehensive performance report"""
        report = [
            "=== Advanced Performance Report ===",
            f"Uptime: {time.time() - self.start_time:.1f}s",
            "",
            "Crypto Cache:",
            f"  {CRYPTO_CACHE.get_stats()}",
            "",
            "Advanced Memory Pool:",
            f"  {ADVANCED_MEMORY_POOL.get_stats()}",
            "",
            "Adaptive Compression:",
            f"  {ADAPTIVE_COMPRESSOR.get_stats()}",
            "",
            "Connection Manager:",
            f"  {CONNECTION_MANAGER.get_stats()}",
            "",
            "Optimizations Enabled:",
        ]
        
        for opt_name, enabled in self.optimizations_enabled.items():
            status = "✅" if enabled else "❌"
            report.append(f"  {status} {opt_name}")
        
        report.append("==============================")
        return "\n".join(report)
    
    def enable_optimization(self, name: str) -> None:
        """Enable specific optimization"""
        if name in self.optimizations_enabled:
            self.optimizations_enabled[name] = True
    
    def disable_optimization(self, name: str) -> None:
        """Disable specific optimization"""
        if name in self.optimizations_enabled:
            self.optimizations_enabled[name] = False

# Global performance optimizer
PERFORMANCE_OPTIMIZER = PerformanceOptimizer()
