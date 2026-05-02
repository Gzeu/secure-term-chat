#!/usr/bin/env python3
"""
Test script to verify security fixes in performance_optimizations.py
"""

import ssl
import time
from performance_optimizations import (
    FramePool, SSLContextPool, MessageCompressor, 
    OptimizedBroadcaster, PerformanceMonitor
)

def test_frame_pool():
    """Test FramePool secure wiping and buffer management"""
    print("Testing FramePool...")
    pool = FramePool()
    
    # Test buffer allocation and return
    buf1 = pool.get_buffer(1024)
    buf1[:10] = b'test data'
    
    # Return buffer (should wipe securely)
    pool.return_buffer(buf1)
    
    # Get buffer again (should be wiped)
    buf2 = pool.get_buffer(1024)
    assert buf2[:10] == b'\x00' * 10, "Buffer not properly wiped"
    
    # Test small buffer handling
    small_buf = pool.get_buffer(2048)
    pool.return_buffer(small_buf)  # Should be returned to pool
    
    stats = pool.get_stats()
    print(f"  FramePool stats: {stats}")
    print("  ✓ FramePool working correctly")

def test_ssl_context_pool():
    """Test SSLContextPool with secure defaults"""
    print("Testing SSLContextPool...")
    
    # Test with default secure mode
    pool = SSLContextPool()
    
    try:
        ctx = pool.get_context("server_cert.pem", "server_key.pem")
        # Should use CERT_REQUIRED by default
        assert ctx.verify_mode == ssl.CERT_REQUIRED, "Default verify_mode should be CERT_REQUIRED"
        
        # Test with explicit verify mode
        ctx2 = pool.get_context("server_cert.pem", "server_key.pem", ssl.CERT_NONE)
        assert ctx2.verify_mode == ssl.CERT_NONE, "Explicit verify_mode not working"
    except FileNotFoundError:
        print("  ⚠ Certificate files not found, skipping SSL context creation test")
        # Test just the pool logic without actual context creation
        assert pool._verify_mode == ssl.CERT_REQUIRED, "Default verify_mode should be CERT_REQUIRED"
    
    stats = pool.get_stats()
    print(f"  SSLPool stats: {stats}")
    print("  ✓ SSLContextPool working correctly")

def test_message_compression():
    """Test MessageCompressor with binary flags"""
    print("Testing MessageCompressor...")
    
    # Test small data (should not be compressed)
    small_data = b"hello world"
    result = MessageCompressor.compress(small_data)
    assert result == small_data, "Small data should be returned as-is"
    decompressed = MessageCompressor.decompress(result)
    assert decompressed == small_data, "Small data decompression failed"
    
    # Test large data (should be compressed)
    large_data = b"x" * 2000
    compressed = MessageCompressor.compress(large_data)
    assert compressed.startswith(b'\x01'), "Large data should have compressed flag"
    decompressed = MessageCompressor.decompress(compressed)
    assert decompressed == large_data, "Large data decompression failed"
    
    # Test corrupted compressed data
    corrupted = b'\x01' + b'corrupted zlib data'
    result = MessageCompressor.decompress(corrupted)
    # Should return payload as-is when decompression fails
    assert result == b'corrupted zlib data', "Corrupted data handling failed"
    
    print("  ✓ MessageCompressor working correctly")

def test_optimized_broadcaster():
    """Test OptimizedBroadcaster stats calculation"""
    print("Testing OptimizedBroadcaster...")
    
    broadcaster = OptimizedBroadcaster()
    
    # Mock peer for testing
    class MockPeer:
        def __init__(self, nick):
            self.nick = nick
            self.queue = type('MockQueue', (), {'put': lambda self, item: None})()
    
    # Test stats calculation
    peers = {"user1": MockPeer("user1"), "user2": MockPeer("user2")}
    
    async def test_broadcast():
        await broadcaster.broadcast_to_room(
            peers, {"user1", "user2"}, b"test_frame"
        )
        
        stats = broadcaster.get_stats()
        assert stats["total_broadcasts"] == 1, "Broadcast count incorrect"
        assert stats["total_recipients"] == 2, "Recipients count incorrect"
        assert stats["avg_recipients"] == 2.0, "Average calculation incorrect"
        
        print(f"  Broadcast stats: {stats}")
    
    import asyncio
    asyncio.run(test_broadcast())
    print("  ✓ OptimizedBroadcaster working correctly")

def test_performance_monitor():
    """Test PerformanceMonitor initialization"""
    print("Testing PerformanceMonitor...")
    
    monitor = PerformanceMonitor()
    
    # Metrics should be empty initially
    assert monitor.metrics == {}, "Metrics should be empty at initialization"
    
    # Update metrics
    monitor.update_metrics()
    
    # Should now have data
    assert "uptime" in monitor.metrics, "Uptime not in metrics after update"
    assert "frame_pool" in monitor.metrics, "Frame pool not in metrics after update"
    
    report = monitor.get_report()
    assert "Performance Report" in report, "Report generation failed"
    
    print("  ✓ PerformanceMonitor working correctly")

def main():
    """Run all security fix tests"""
    print("Running security fix tests...\n")
    
    try:
        test_frame_pool()
        print()
        test_ssl_context_pool()
        print()
        test_message_compression()
        print()
        test_optimized_broadcaster()
        print()
        test_performance_monitor()
        print()
        print("🎉 All security fixes verified successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
