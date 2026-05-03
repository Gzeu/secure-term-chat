#!/usr/bin/env python3
"""
Launch script for secure-term-chat Server with Auto-scaling
Easy entry point for intelligent resource management
"""

import sys
import asyncio
import logging
import signal
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from server import ChatServer

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\n👋 Received signal {signum}, shutting down...")
    sys.exit(0)

def main():
    """Launch the server with auto-scaling"""
    print("🚀 Starting secure-term-chat Server with Auto-scaling...")
    print("⚡ Intelligent resource management and optimization")
    print("🔒 End-to-end encryption with TLS support")
    print("📊 Real-time performance monitoring")
    print("🌐 P2P WebRTC communication support")
    print("─" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Create server instance with all features enabled
        server = ChatServer(use_tls=True, pq_mode=True)
        
        print(f"🔐 Server fingerprint: {server._server_identity.fingerprint()}")
        print(f"📊 Auto-scaling: {'✅ Enabled' if server._auto_scaling_enabled else '❌ Disabled'}")
        print(f"🌐 P2P WebRTC: {'✅ Available' if server._pq_mode else '❌ Disabled'}")
        print(f"🔒 TLS Encryption: ✅ Enabled")
        
        # Start server
        print("🚀 Starting server on localhost:12345...")
        print("📊 Auto-scaling will optimize resources automatically")
        print("Press Ctrl+C to stop the server")
        
        asyncio.run(server.start("localhost", 12345))
        
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
