#!/usr/bin/env python3
"""
Performance Optimizations for secure-term-chat
- Frame Pooling
- Message Batching  
- Connection Pooling
- Compression
"""

import asyncio
import zlib
import time
import ssl
from collections import deque
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import weakref

# ──────────────────────────────────────────────────
# Frame Pooling - Reduce GC Pressure
# ──────────────────────────────────────────────────
class FramePool:
    """Pool of reusable frame buffers to reduce memory allocation"""
    
    def __init__(self, max_size: int = 100):
        self._pool: deque = deque(maxlen=max_size)
        self._max_size = max_size
        self._hits = 0
        self._misses = 0
    
    def get_buffer(self, size: int = 2 * 1024 * 1024) -> bytearray:
        """Get a buffer from pool or create new one"""
        if self._pool:
            buf = self._pool.popleft()
            if len(buf) >= size:
                self._hits += 1
                return buf
            else:
                # Buffer too small, discard and create new
                self._misses += 1
                return bytearray(size)
        else:
            self._misses += 1
            return bytearray(size)
    
    def return_buffer(self, buf: bytearray) -> None:
        """Return buffer to pool after wiping"""
        if len(buf) >= 1024:  # Only pool buffers >= 1KB
            buf[:] = b'\x00' * len(buf)  # Secure wipe
            if len(self._pool) < self._max_size:
                self._pool.append(buf)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "pool_size": len(self._pool),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%"
        }

# Global frame pool instance
FRAME_POOL = FramePool()

# ──────────────────────────────────────────────────
# Message Batching - Reduce Syscall Overhead
# ──────────────────────────────────────────────────
@dataclass
class MessageBatch:
    """Batch of messages to be sent together"""
    messages: List[bytes]
    created_at: float
    max_size: int = 64 * 1024  # 64KB max batch size
    
    def add_message(self, msg: bytes) -> bool:
        """Add message to batch, return False if batch is full"""
        if len(self.messages) >= 10:  # Max 10 messages per batch
            return False
        
        total_size = sum(len(m) for m in self.messages) + len(msg)
        if total_size > self.max_size:
            return False
        
        self.messages.append(msg)
        return True
    
    def is_ready(self, timeout: float = 0.01) -> bool:
        """Check if batch is ready to send (timeout or full)"""
        return (
            len(self.messages) >= 10 or 
            (time.time() - self.created_at) >= timeout
        )
    
    def combine(self) -> bytes:
        """Combine all messages into single buffer"""
        return b''.join(self.messages)

class BatchSender:
    """Handles batching of outgoing messages"""
    
    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer
        self._current_batch: Optional[MessageBatch] = None
        self._send_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
    
    async def send_message(self, data: bytes) -> None:
        """Send message with batching"""
        async with self._lock:
            if self._current_batch is None:
                self._current_batch = MessageBatch(messages=[], created_at=time.time())
                # Schedule batch send
                if self._send_task is None or self._send_task.done():
                    self._send_task = asyncio.create_task(self._batch_sender_loop())
            
            if not self._current_batch.add_message(data):
                # Batch full, send immediately
                await self._flush_batch()
                # Create new batch with this message
                self._current_batch = MessageBatch(messages=[data], created_at=time.time())
    
    async def _batch_sender_loop(self) -> None:
        """Background task to flush batches when ready"""
        while True:
            await asyncio.sleep(0.01)  # Check every 10ms
            async with self._lock:
                if self._current_batch and self._current_batch.is_ready():
                    await self._flush_batch()
                if self._current_batch is None:
                    break  # No more batches, exit
    
    async def _flush_batch(self) -> None:
        """Flush current batch to network"""
        if not self._current_batch or not self._current_batch.messages:
            return
        
        combined = self._current_batch.combine()
        self.writer.write(combined)
        await self.writer.drain()
        self._current_batch = None

# ──────────────────────────────────────────────────
# Connection Pooling - Reuse SSL Contexts
# ──────────────────────────────────────────────────
class SSLContextPool:
    """Pool of reusable SSL contexts"""
    
    def __init__(self, max_size: int = 10):
        self._pool: deque = deque(maxlen=max_size)
        self._contexts_in_use: weakref.WeakSet = weakref.WeakSet()
        self._hits = 0
        self._misses = 0
    
    def get_context(self, cert_file: str, key_file: str) -> ssl.SSLContext:
        """Get SSL context from pool or create new one"""
        # Simple implementation - in production, would match by cert/key
        if self._pool:
            ctx = self._pool.popleft()
            self._hits += 1
            self._contexts_in_use.add(ctx)
            return ctx
        else:
            self._misses += 1
            ctx = self._create_context(cert_file, key_file)
            self._contexts_in_use.add(ctx)
            return ctx
    
    def _create_context(self, cert_file: str, key_file: str) -> ssl.SSLContext:
        """Create new SSL context"""
        import ssl
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert_file, key_file)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    def return_context(self, ctx: ssl.SSLContext) -> None:
        """Return context to pool"""
        if ctx in self._contexts_in_use and len(self._pool) < self._pool.maxlen:
            self._pool.append(ctx)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "pool_size": len(self._pool),
            "in_use": len(self._contexts_in_use),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%"
        }

# Global SSL context pool
SSL_POOL = SSLContextPool()

# ──────────────────────────────────────────────────
# Compression - For Large Messages
# ──────────────────────────────────────────────────
class MessageCompressor:
    """Handles compression of large messages"""
    
    COMPRESSION_THRESHOLD = 1024  # Compress messages > 1KB
    
    @staticmethod
    def compress(data: bytes) -> bytes:
        """Compress data if beneficial"""
        if len(data) < MessageCompressor.COMPRESSION_THRESHOLD:
            return data
        
        compressed = zlib.compress(data, level=6)
        
        # Only use compression if it reduces size
        if len(compressed) < len(data) * 0.9:  # At least 10% reduction
            return b'COMPRESSED:' + compressed
        else:
            return data
    
    @staticmethod
    def decompress(data: bytes) -> bytes:
        """Decompress data if compressed"""
        if data.startswith(b'COMPRESSED:'):
            return zlib.decompress(data[11:])
        else:
            return data

# ──────────────────────────────────────────────────
# Optimized Broadcast - Event-driven with asyncio.gather
# ──────────────────────────────────────────────────
class OptimizedBroadcaster:
    """Optimized room broadcasting with asyncio.gather"""
    
    def __init__(self):
        self._broadcast_stats = {
            "total_broadcasts": 0,
            "total_messages": 0,
            "failed_sends": 0,
            "avg_recipients": 0
        }
    
    async def broadcast_to_room(
        self, 
        peers: Dict[str, Any], 
        room_members: set, 
        frame: bytes, 
        exclude: str = ""
    ) -> None:
        """Broadcast frame to all room members concurrently"""
        recipients = [
            peers[nick] for nick in room_members 
            if nick != exclude and nick in peers
        ]
        
        if not recipients:
            return
        
        # Update stats
        self._broadcast_stats["total_broadcasts"] += 1
        self._broadcast_stats["total_messages"] += len(recipients)
        self._broadcast_stats["avg_recipients"] = (
            (self._broadcast_stats["avg_recipients"] * (self._broadcast_stats["total_broadcasts"] - 1) + len(recipients)) /
            self._broadcast_stats["total_broadcasts"]
        )
        
        # Concurrent send with error handling
        tasks = []
        for peer in recipients:
            task = asyncio.create_task(
                self._safe_send_to_peer(peer, frame),
                name=f"send_to_{peer.nick}"
            )
            tasks.append(task)
        
        # Wait for all sends with timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
            self._broadcast_stats["failed_sends"] += len(tasks)
    
    async def _safe_send_to_peer(self, peer: Any, frame: bytes) -> None:
        """Safely send frame to peer with error handling"""
        try:
            await peer.queue.put(frame)
        except asyncio.QueueFull:
            self._broadcast_stats["failed_sends"] += 1
        except Exception:
            self._broadcast_stats["failed_sends"] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get broadcast statistics"""
        return self._broadcast_stats.copy()

# Global broadcaster instance
BROADCASTER = OptimizedBroadcaster()

# ──────────────────────────────────────────────────
# Performance Monitor
# ──────────────────────────────────────────────────
class PerformanceMonitor:
    """Monitor and report performance metrics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            "frame_pool": FRAME_POOL.get_stats(),
            "ssl_pool": SSL_POOL.get_stats(),
            "broadcast": BROADCASTER.get_stats(),
            "uptime": time.time() - self.start_time
        }
    
    def update_metrics(self) -> None:
        """Update all performance metrics"""
        self.metrics.update({
            "frame_pool": FRAME_POOL.get_stats(),
            "ssl_pool": SSL_POOL.get_stats(),
            "broadcast": BROADCASTER.get_stats(),
            "uptime": time.time() - self.start_time
        })
    
    def get_report(self) -> str:
        """Get formatted performance report"""
        self.update_metrics()
        
        report = [
            "=== Performance Report ===",
            f"Uptime: {self.metrics['uptime']:.1f}s",
            "",
            "Frame Pool:",
            f"  Size: {self.metrics['frame_pool']['pool_size']}/{self.metrics['frame_pool']['max_size']}",
            f"  Hit Rate: {self.metrics['frame_pool']['hit_rate']}",
            "",
            "SSL Pool:",
            f"  Size: {self.metrics['ssl_pool']['pool_size']}",
            f"  In Use: {self.metrics['ssl_pool']['in_use']}",
            f"  Hit Rate: {self.metrics['ssl_pool']['hit_rate']}",
            "",
            "Broadcast:",
            f"  Total: {self.metrics['broadcast']['total_broadcasts']}",
            f"  Messages: {self.metrics['broadcast']['total_messages']}",
            f"  Failed: {self.metrics['broadcast']['failed_sends']}",
            f"  Avg Recipients: {self.metrics['broadcast']['avg_recipients']:.1f}",
            "========================="
        ]
        
        return "\n".join(report)

# Global performance monitor
PERF_MONITOR = PerformanceMonitor()
