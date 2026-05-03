"""
Performance optimizations for secure-term-chat
"""

from performance_monitor import MetricsCollector
import asyncio

# Global instances
PERF_MONITOR = MetricsCollector()

# Frame pooling for network optimization
class FramePool:
    def __init__(self, size=100):
        self.size = size
        self.pool = asyncio.Queue(maxsize=size)
        self._initialized = False
    
    async def get(self):
        if not self._initialized:
            return {}
        try:
            return self.pool.get_nowait()
        except asyncio.QueueEmpty:
            return {}
    
    async def put(self, frame):
        if self._initialized and self.pool.qsize() < self.size:
            try:
                self.pool.put_nowait(frame)
            except asyncio.QueueFull:
                pass

FRAME_POOL = FramePool()

# SSL connection pooling
class SSLPool:
    def __init__(self):
        self.connections = {}
        self.contexts = {}
    
    def get(self, host):
        return self.connections.get(host)
    
    def add(self, host, connection):
        self.connections[host] = connection
    
    def remove(self, host):
        self.connections.pop(host, None)
    
    def get_context(self, cert_file, key_file, verify_mode):
        """Get or create SSL context for TLS connections"""
        import ssl
        
        context_key = f"{cert_file}:{key_file}:{verify_mode}"
        
        if context_key not in self.contexts:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_file, key_file)
            context.verify_mode = verify_mode
            self.contexts[context_key] = context
        
        return self.contexts[context_key]

SSL_POOL = SSLPool()

# Broadcaster for efficient message distribution
class Broadcaster:
    def __init__(self):
        self.subscribers = set()
    
    def subscribe(self, callback):
        self.subscribers.add(callback)
    
    def unsubscribe(self, callback):
        self.subscribers.discard(callback)
    
    async def broadcast(self, message):
        for callback in self.subscribers:
            try:
                await callback(message)
            except Exception:
                pass

BROADCASTER = Broadcaster()
