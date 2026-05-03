#!/usr/bin/env python3
"""
Launch script for WebRTC Signaling Server
Easy entry point for P2P communication support
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from signaling_server import create_signaling_server, is_signaling_available

def main():
    """Launch the signaling server"""
    print("🌐 Starting WebRTC Signaling Server...")
    print("📡 P2P communication support for secure-term-chat")
    print("🔗 WebSocket-based signaling for peer connections")
    print("─" * 50)
    
    # Check availability
    if not is_signaling_available():
        print("❌ websockets not available")
        print("Please install: pip install websockets")
        sys.exit(1)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    async def run_server():
        """Run the signaling server"""
        server = create_signaling_server()
        
        try:
            if await server.start():
                print(f"🚀 Signaling server started on ws://{server.host}:{server.port}")
                print("📊 Waiting for peer connections...")
                print("Press Ctrl+C to stop")
                
                # Start cleanup loop
                cleanup_task = asyncio.create_task(server._cleanup_loop())
                
                try:
                    while server.running:
                        await asyncio.sleep(1)
                        
                        # Print stats every 30 seconds
                        stats = server.get_stats()
                        if stats['active_connections'] > 0:
                            print(f"📊 Active: {stats['active_connections']} | Messages: {stats['messages_relayed']}")
                        await asyncio.sleep(30)
                        
                except KeyboardInterrupt:
                    print("\n👋 Shutting down...")
                
                cleanup_task.cancel()
                await server.stop()
                print("✅ Server stopped")
            else:
                print("❌ Failed to start server")
                
        except Exception as e:
            print(f"❌ Server error: {e}")
    
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
