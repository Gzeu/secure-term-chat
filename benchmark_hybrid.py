#!/usr/bin/env python3
"""
Hybrid Cryptography Performance Benchmarking
Tests performance impact of Post-Quantum hybrid cryptography

This module benchmarks:
- Key exchange performance (classical vs hybrid)
- Message encryption/decryption
- Memory usage
- Throughput analysis
"""

import time
import os
import gc
import psutil
from typing import Dict, List, Tuple
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from hybrid_crypto import HybridCryptoEngine, HybridIdentity
from double_ratchet_custom import SimpleRatchet


@dataclass
class BenchmarkResult:
    """Benchmark result with timing and memory metrics"""
    operation: str
    duration_ms: float
    memory_mb: float
    iterations: int
    avg_per_iteration: float


class HybridCryptoBenchmark:
    """Performance benchmarking for hybrid cryptography"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.results: List[BenchmarkResult] = []
    
    def _measure_memory(self) -> float:
        """Get current memory usage in MB"""
        return self.process.memory_info().rss / 1024 / 1024
    
    def _benchmark_operation(self, operation_name: str, func, iterations: int = 100) -> BenchmarkResult:
        """Benchmark an operation with memory measurement"""
        # Force garbage collection before measurement
        gc.collect()
        
        # Measure initial memory
        initial_memory = self._measure_memory()
        
        # Benchmark operation
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            func()
        
        end_time = time.perf_counter()
        final_memory = self._measure_memory()
        
        # Calculate metrics
        duration_ms = (end_time - start_time) * 1000
        memory_delta = final_memory - initial_memory
        avg_per_iteration = duration_ms / iterations
        
        result = BenchmarkResult(
            operation=operation_name,
            duration_ms=duration_ms,
            memory_mb=memory_delta,
            iterations=iterations,
            avg_per_iteration=avg_per_iteration
        )
        
        self.results.append(result)
        return result
    
    def benchmark_classical_key_exchange(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark classical X25519 key exchange"""
        engine = HybridCryptoEngine(pq_mode=False)
        
        def key_exchange():
            alice = engine.generate_identity()
            bob = engine.generate_identity()
            
            # Classical key exchange only
            kex = engine.hybrid_key_exchange(alice, bob.x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ))
        
        return self._benchmark_operation("Classical Key Exchange", key_exchange, iterations)
    
    def benchmark_hybrid_key_exchange(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark hybrid X25519 + ML-KEM key exchange"""
        engine = HybridCryptoEngine(pq_mode=True)
        
        def key_exchange():
            alice = engine.generate_identity()
            bob = engine.generate_identity()
            
            # Hybrid key exchange with PQ
            kex = engine.hybrid_key_exchange(
                alice, 
                bob.x25519_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ),
                bob.kem_public_key
            )
        
        return self._benchmark_operation("Hybrid Key Exchange", key_exchange, iterations)
    
    def benchmark_classical_encryption(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark classical encryption"""
        engine = HybridCryptoEngine(pq_mode=False)
        alice = engine.generate_identity()
        bob = engine.generate_identity()
        
        # Get classical key
        kex = engine.hybrid_key_exchange(alice, bob.x25519_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        
        test_message = b"Hello, benchmarking world!" * 10  # ~350 bytes
        
        def encrypt_decrypt():
            ciphertext, metadata = engine.encrypt_message(test_message, hybrid_key=kex.hybrid_key)
            decrypted = engine.decrypt_message(ciphertext, metadata, hybrid_key=kex.hybrid_key)
            assert decrypted == test_message
        
        return self._benchmark_operation("Classical Encryption", encrypt_decrypt, iterations)
    
    def benchmark_hybrid_encryption(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark hybrid encryption with ratchet"""
        engine = HybridCryptoEngine(pq_mode=True)
        alice = engine.generate_identity()
        bob = engine.generate_identity()
        
        # Get hybrid key
        kex = engine.hybrid_key_exchange(
            alice, 
            bob.x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            bob.kem_public_key
        )
        
        # Create ratchets for Alice and Bob
        alice_ratchet = SimpleRatchet(kex.hybrid_key)
        bob_ratchet = SimpleRatchet(kex.hybrid_key)
        test_message = b"Hello, benchmarking world!" * 10  # ~350 bytes
        
        def encrypt_decrypt():
            # Alice encrypts
            ciphertext, nonce, msg_num = alice_ratchet.encrypt(test_message)
            # Bob decrypts (simplified - using same key for test)
            decrypted = bob_ratchet.decrypt(ciphertext, nonce, msg_num)
            assert decrypted == test_message
        
        return self._benchmark_operation("Hybrid Encryption (Ratchet)", encrypt_decrypt, iterations)
    
    def benchmark_identity_generation(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark identity generation"""
        engine_classical = HybridCryptoEngine(pq_mode=False)
        engine_hybrid = HybridCryptoEngine(pq_mode=True)
        
        def generate_classical():
            engine_classical.generate_identity()
        
        def generate_hybrid():
            engine_hybrid.generate_identity()
        
        classical_result = self._benchmark_operation("Classical Identity Generation", generate_classical, iterations)
        hybrid_result = self._benchmark_operation("Hybrid Identity Generation", generate_hybrid, iterations)
        
        return classical_result, hybrid_result
    
    def benchmark_fingerprint_generation(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark fingerprint generation"""
        engine = HybridCryptoEngine(pq_mode=True)
        identity = engine.generate_identity()
        
        def generate_fingerprint():
            fp = identity.fingerprint()
        
        return self._benchmark_operation("Hybrid Fingerprint Generation", generate_fingerprint, iterations)
    
    def run_all_benchmarks(self) -> Dict[str, List[BenchmarkResult]]:
        """Run all benchmarks and return results"""
        print("🚀 Starting Hybrid Cryptography Benchmarks...")
        print("=" * 60)
        
        # Clear previous results
        self.results = []
        
        # Key Exchange Benchmarks
        print("🔑 Key Exchange Benchmarks...")
        classical_kex = self.benchmark_classical_key_exchange(50)
        hybrid_kex = self.benchmark_hybrid_key_exchange(50)
        
        # Encryption Benchmarks
        print("🔒 Encryption Benchmarks...")
        classical_enc = self.benchmark_classical_encryption(500)
        hybrid_enc = self.benchmark_hybrid_encryption(500)
        
        # Identity Generation Benchmarks
        print("🆔 Identity Generation Benchmarks...")
        classical_id, hybrid_id = self.benchmark_identity_generation(50)
        
        # Fingerprint Generation
        print("🔍 Fingerprint Generation Benchmarks...")
        fingerprint_gen = self.benchmark_fingerprint_generation(500)
        
        return {
            "key_exchange": [classical_kex, hybrid_kex],
            "encryption": [classical_enc, hybrid_enc],
            "identity": [classical_id, hybrid_id],
            "fingerprint": [fingerprint_gen]
        }
    
    def print_results(self, results: Dict[str, List[BenchmarkResult]]):
        """Print formatted benchmark results"""
        print("\n" + "=" * 60)
        print("📊 BENCHMARK RESULTS")
        print("=" * 60)
        
        # Key Exchange Comparison
        print("\n🔑 KEY EXCHANGE PERFORMANCE:")
        kex_results = results["key_exchange"]
        for result in kex_results:
            print(f"  {result.operation}:")
            print(f"    Total: {result.duration_ms:.2f}ms ({result.iterations} iterations)")
            print(f"    Average: {result.avg_per_iteration:.2f}ms per operation")
            print(f"    Memory: +{result.memory_mb:.2f}MB")
        
        kex_overhead = (kex_results[1].avg_per_iteration / kex_results[0].avg_per_iteration - 1) * 100
        print(f"  📈 Hybrid Overhead: {kex_overhead:.1f}%")
        
        # Encryption Comparison
        print("\n🔒 ENCRYPTION PERFORMANCE:")
        enc_results = results["encryption"]
        for result in enc_results:
            print(f"  {result.operation}:")
            print(f"    Total: {result.duration_ms:.2f}ms ({result.iterations} iterations)")
            print(f"    Average: {result.avg_per_iteration:.2f}ms per operation")
            print(f"    Memory: +{result.memory_mb:.2f}MB")
        
        enc_overhead = (enc_results[1].avg_per_iteration / enc_results[0].avg_per_iteration - 1) * 100
        print(f"  📈 Hybrid Overhead: {enc_overhead:.1f}%")
        
        # Identity Generation Comparison
        print("\n🆔 IDENTITY GENERATION PERFORMANCE:")
        id_results = results["identity"]
        for result in id_results:
            print(f"  {result.operation}:")
            print(f"    Total: {result.duration_ms:.2f}ms ({result.iterations} iterations)")
            print(f"    Average: {result.avg_per_iteration:.2f}ms per operation")
            print(f"    Memory: +{result.memory_mb:.2f}MB")
        
        id_overhead = (id_results[1].avg_per_iteration / id_results[0].avg_per_iteration - 1) * 100
        print(f"  📈 Hybrid Overhead: {id_overhead:.1f}%")
        
        # Fingerprint Generation
        print("\n🔍 FINGERPRINT GENERATION:")
        fp_result = results["fingerprint"][0]
        print(f"  {fp_result.operation}:")
        print(f"    Total: {fp_result.duration_ms:.2f}ms ({fp_result.iterations} iterations)")
        print(f"    Average: {fp_result.avg_per_iteration:.3f}ms per operation")
        print(f"    Memory: +{fp_result.memory_mb:.2f}MB")
        
        # Summary
        print("\n" + "=" * 60)
        print("📈 PERFORMANCE SUMMARY")
        print("=" * 60)
        print(f"Key Exchange Overhead: {kex_overhead:.1f}%")
        print(f"Encryption Overhead: {enc_overhead:.1f}%")
        print(f"Identity Generation Overhead: {id_overhead:.1f}%")
        
        # Performance Assessment
        avg_overhead = (kex_overhead + enc_overhead + id_overhead) / 3
        print(f"\n🎯 Average Performance Overhead: {avg_overhead:.1f}%")
        
        if avg_overhead < 50:
            print("✅ Performance is EXCELLENT - Minimal impact!")
        elif avg_overhead < 100:
            print("✅ Performance is GOOD - Acceptable overhead!")
        elif avg_overhead < 200:
            print("⚠️  Performance is MODERATE - Noticeable but usable!")
        else:
            print("❌ Performance is HIGH - May need optimization!")
        
        # Memory Assessment
        total_memory = sum(result.memory_mb for result_group in results.values() for result in result_group)
        print(f"\n💾 Total Memory Usage: +{total_memory:.2f}MB")
        
        if total_memory < 10:
            print("✅ Memory usage is EXCELLENT!")
        elif total_memory < 50:
            print("✅ Memory usage is GOOD!")
        else:
            print("⚠️  Memory usage is MODERATE!")


def main():
    """Run comprehensive hybrid crypto benchmarks"""
    benchmark = HybridCryptoBenchmark()
    results = benchmark.run_all_benchmarks()
    benchmark.print_results(results)


if __name__ == "__main__":
    main()
