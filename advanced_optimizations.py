"""
Advanced optimizations for secure-term-chat
"""

import asyncio
from typing import Dict, List, Optional

# Connection manager for efficient connection handling
class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, asyncio.Queue] = {}
        self.active_connections: set = set()
    
    def add_connection(self, conn_id: str, queue: asyncio.Queue):
        self.connections[conn_id] = queue
        self.active_connections.add(conn_id)
    
    def remove_connection(self, conn_id: str):
        self.connections.pop(conn_id, None)
        self.active_connections.discard(conn_id)
    
    def get_connection(self, conn_id: str) -> Optional[asyncio.Queue]:
        return self.connections.get(conn_id)
    
    def get_active_count(self) -> int:
        return len(self.active_connections)

# Message buffer for batch processing
class MessageBuffer:
    def __init__(self, batch_size: int = 100, flush_interval: float = 0.1):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer: List[dict] = []
        self.last_flush = asyncio.get_event_loop().time()
    
    async def add(self, message: dict) -> bool:
        self.buffer.append(message)
        
        current_time = asyncio.get_event_loop().time()
        if (len(self.buffer) >= self.batch_size or 
            current_time - self.last_flush >= self.flush_interval):
            await self.flush()
            return True
        return False
    
    async def flush(self) -> List[dict]:
        messages = self.buffer.copy()
        self.buffer.clear()
        self.last_flush = asyncio.get_event_loop().time()
        return messages

# Rate limiter for connection protection
class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}
    
    async def check_rate_limit(self, client_id: str) -> bool:
        current_time = asyncio.get_event_loop().time()
        
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        # Remove old requests outside the window
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if current_time - req_time < self.window_seconds
        ]
        
        # Check if under limit
        if len(self.requests[client_id]) < self.max_requests:
            self.requests[client_id].append(current_time)
            return True
        
        return False

# Crypto cache for frame verification
class CryptoCache:
    def __init__(self, max_size=1000):
        self.cache = {}
        self.max_size = max_size
    
    def get(self, key):
        return self.cache.get(key)
    
    def put(self, key, value):
        if len(self.cache) >= self.max_size:
            # Remove oldest entry (simple FIFO)
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        self.cache[key] = value

# Advanced memory pool for efficient memory management
class AdvancedMemoryPool:
    def __init__(self):
        self.pools = {}
    
    def get_buffer(self, size):
        if size not in self.pools:
            self.pools[size] = []
        
        if self.pools[size]:
            return self.pools[size].pop()
        return bytearray(size)
    
    def return_buffer(self, buffer):
        size = len(buffer)
        if size not in self.pools:
            self.pools[size] = []
        
        if len(self.pools[size]) < 100:  # Limit pool size
            self.pools[size].append(buffer)

# Adaptive compressor for dynamic compression
class AdaptiveCompressor:
    def __init__(self):
        self.compression_level = 6
        self.threshold = 1024  # Only compress data larger than this
    
    def should_compress(self, data):
        return len(data) > self.threshold
    
    def compress(self, data):
        if not self.should_compress(data):
            return data
        
        import zlib
        try:
            return zlib.compress(data, level=self.compression_level)
        except:
            return data
    
    def decompress(self, data):
        import zlib
        try:
            return zlib.decompress(data)
        except:
            return data

# Performance optimizer to manage all optimizations
class PerformanceOptimizer:
    def __init__(self):
        self.optimizations_enabled = {
            "crypto_cache": True,
            "adaptive_compression": True,
            "advanced_memory": True,
            "connection_pooling": True
        }
    
    def disable_optimization(self, optimization_name):
        self.optimizations_enabled[optimization_name] = False
    
    def enable_optimization(self, optimization_name):
        self.optimizations_enabled[optimization_name] = True

# Global instances
CONNECTION_MANAGER = ConnectionManager()
MESSAGE_BUFFER = MessageBuffer()
RATE_LIMITER = RateLimiter()
CRYPTO_CACHE = CryptoCache()
ADVANCED_MEMORY_POOL = AdvancedMemoryPool()
ADAPTIVE_COMPRESSOR = AdaptiveCompressor()
PERFORMANCE_OPTIMIZER = PerformanceOptimizer()
