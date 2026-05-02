#!/usr/bin/env python3
"""
Comprehensive test suite for advanced optimizations
"""

import asyncio
import time
import hashlib
from advanced_optimizations import (
    CryptoCache, AdvancedMemoryPool, AdaptiveCompressor,
    ZeroCopyBuffer, ConnectionManager, PerformanceOptimizer
)

def test_crypto_cache():
    """Test cryptographic operation caching"""
    print("Testing CryptoCache...")
    
    cache = CryptoCache(max_size=10)
    
    # Test cache miss
    result = cache.get("test_key")
    assert result is None, "Cache should return None for miss"
    
    # Test cache put and hit
    test_data = b"test cryptographic data"
    cache.put("test_key", test_data)
    result = cache.get("test_key")
    assert result == test_data, "Cache should return correct data"
    
    # Test LRU eviction
    for i in range(15):
        cache.put(f"key_{i}", f"data_{i}".encode())
    
    # Original key should be evicted
    result = cache.get("test_key")
    assert result is None, "LRU eviction should work"
    
    stats = cache.get_stats()
    assert stats["size"] == 10, "Cache size should be at max"
    assert stats["hits"] > 0, "Should have cache hits"
    
    print(f"  ✓ CryptoCache working: {stats}")

def test_advanced_memory_pool():
    """Test advanced memory pool with size-based management"""
    print("Testing AdvancedMemoryPool...")
    
    pool = AdvancedMemoryPool(max_memory=1024 * 1024)  # 1MB
    
    # Test block allocation
    block1 = pool.get_block(1024)
    block2 = pool.get_block(2048)
    
    assert len(block1.data) >= 1024, "Block should be at least requested size"
    assert len(block2.data) >= 2048, "Block should be at least requested size"
    
    # Test block reuse
    pool.return_block(block1)
    block3 = pool.get_block(1024)
    
    # Should reuse the same block (same size)
    assert block3 is block1, "Should reuse returned block"
    
    stats = pool.get_stats()
    assert stats["reuses"] > 0, "Should have block reuses"
    assert stats["allocations"] >= 2, "Should have allocations"
    
    print(f"  ✓ AdvancedMemoryPool working: {stats}")

def test_adaptive_compressor():
    """Test adaptive compression with threshold adjustment"""
    print("Testing AdaptiveCompressor...")
    
    compressor = AdaptiveCompressor()
    
    # Test small data (should not compress)
    small_data = b"hello world"
    result, compressed = compressor.compress(small_data)
    assert not compressed, "Small data should not be compressed"
    assert result == small_data, "Small data should be returned as-is"
    
    # Test large data (should compress)
    large_data = b"x" * 2000
    result, compressed = compressor.compress(large_data)
    assert compressed, "Large data should be compressed"
    assert result.startswith(b'\x01'), "Compressed data should have flag"
    
    # Test decompression
    decompressed = compressor.decompress(result)
    assert decompressed == large_data, "Decompression should restore original"
    
    # Test threshold adjustment
    initial_threshold = compressor.get_stats()["threshold"]
    
    # Simulate many compression operations
    for _ in range(150):
        compressor.compress(b"y" * 1500)
    
    new_threshold = compressor.get_stats()["threshold"]
    # Threshold should have adjusted
    assert new_threshold != initial_threshold, "Threshold should adjust based on performance"
    
    print(f"  ✓ AdaptiveCompressor working: threshold {initial_threshold} -> {new_threshold}")

def test_zero_copy_buffer():
    """Test zero-copy buffer operations"""
    print("Testing ZeroCopyBuffer...")
    
    buffer = ZeroCopyBuffer(initial_size=1024)
    
    # Test write and read
    test_data = b"hello world"
    buffer.write(test_data)
    
    view = buffer.read(5)
    assert bytes(view) == b"hello", "Should read correct data"
    
    # Test multiple reads
    view2 = buffer.read(6)
    assert bytes(view2) == b" world", "Should continue reading correctly"
    
    # Test buffer expansion
    large_data = b"x" * 2000
    buffer.write(large_data)
    
    view3 = buffer.read(2000)
    assert len(view3) == 2000, "Should handle buffer expansion"
    
    # Test flush
    buffer.flush()
    view4 = buffer.read(10)
    assert len(view4) == 0, "Flush should reset buffer"
    
    print("  ✓ ZeroCopyBuffer working correctly")

def test_connection_manager():
    """Test connection state management"""
    print("Testing ConnectionManager...")
    
    manager = ConnectionManager(cleanup_interval=1.0)
    
    # Test connection creation
    conn1 = manager.get_connection("user1")
    conn2 = manager.get_connection("user2")
    
    assert conn1.peer_id == "user1", "Should create connection state"
    assert conn2.peer_id == "user2", "Should create second connection"
    
    # Test activity update
    conn1.update_activity()
    initial_activity = conn1.last_activity
    
    time.sleep(0.1)
    conn1.update_activity()
    assert conn1.last_activity > initial_activity, "Should update activity"
    
    # Test stats
    conn1.message_count = 10
    conn1.bytes_sent = 1024
    stats = conn1.get_stats()
    assert stats["message_count"] == 10, "Should track message count"
    assert stats["bytes_sent"] == 1024, "Should track bytes sent"
    
    # Test cleanup
    manager.remove_connection("user1")
    assert "user1" not in manager._connections, "Should remove connection"
    
    print(f"  ✓ ConnectionManager working: {manager.get_stats()}")

def test_performance_optimizer():
    """Test performance optimizer coordination"""
    print("Testing PerformanceOptimizer...")
    
    optimizer = PerformanceOptimizer()
    
    # Test optimization control
    assert optimizer.optimizations_enabled["crypto_cache"], "Should enable crypto cache by default"
    
    optimizer.disable_optimization("crypto_cache")
    assert not optimizer.optimizations_enabled["crypto_cache"], "Should disable optimization"
    
    optimizer.enable_optimization("crypto_cache")
    assert optimizer.optimizations_enabled["crypto_cache"], "Should re-enable optimization"
    
    # Test comprehensive report
    report = optimizer.get_comprehensive_report()
    assert "Advanced Performance Report" in report, "Should generate report"
    assert "Crypto Cache:" in report, "Should include crypto cache stats"
    assert "Connection Manager:" in report, "Should include connection stats"
    
    print("  ✓ PerformanceOptimizer working correctly")

async def test_integration():
    """Test integration of all optimizations"""
    print("Testing integration...")
    
    # Create components
    cache = CryptoCache()
    pool = AdvancedMemoryPool()
    compressor = AdaptiveCompressor()
    manager = ConnectionManager()
    
    # Simulate server operations
    for i in range(10):
        # Simulate message processing
        message = f"message_{i}".encode()
        
        # Cache cryptographic operations
        message_hash = hashlib.sha256(message).hexdigest()
        cache.put(message_hash, message)
        
        # Try to retrieve from cache (this will create hits)
        cached_message = cache.get(message_hash)
        assert cached_message == message, f"Cache should return correct message for {message_hash}"
        
        # Apply compression
        compressed, was_compressed = compressor.compress(message)
        
        # Use memory pool
        block = pool.get_block(len(compressed))
        block.data[:len(compressed)] = compressed
        pool.return_block(block)
        
        # Update connection state
        conn = manager.get_connection(f"user_{i}")
        conn.message_count += 1
        conn.bytes_sent += len(compressed)
        conn.update_activity()
    
    # Verify integration results
    cache_stats = cache.get_stats()
    pool_stats = pool.get_stats()
    manager_stats = manager.get_stats()
    
    assert cache_stats["hits"] >= 10, "Should have cache hits from retrievals"
    assert pool_stats["reuses"] > 0, "Should have memory reuses"
    assert manager_stats["active_connections"] == 10, "Should have active connections"
    
    print(f"  ✓ Integration successful:")
    print(f"    Cache: {cache_stats['hit_rate']}")
    print(f"    Memory: {pool_stats['utilization']}")
    print(f"    Connections: {manager_stats['active_connections']}")

def main():
    """Run all advanced optimization tests"""
    print("Running advanced optimization tests...\n")
    
    try:
        test_crypto_cache()
        print()
        test_advanced_memory_pool()
        print()
        test_adaptive_compressor()
        print()
        test_zero_copy_buffer()
        print()
        test_connection_manager()
        print()
        test_performance_optimizer()
        print()
        asyncio.run(test_integration())
        print()
        print("🚀 All advanced optimizations verified successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
