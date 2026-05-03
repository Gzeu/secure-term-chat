#!/usr/bin/env python3
"""
WebRTC Signaling Server for secure-term-chat
Simple WebSocket-based signaling for P2P connections
"""

import asyncio
import json
import logging
import time
from typing import Dict, Set, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
except ImportError:
    websockets = None

log = logging.getLogger(__name__)

@dataclass
class ConnectedPeer:
    """Connected peer information"""
    websocket: WebSocketServerProtocol
    peer_id: str
    nickname: str
    fingerprint: str
    room: str
    capabilities: List[str]
    connected_at: float
    last_ping: float
    
    def __post_init__(self):
        if self.connected_at is None:
            self.connected_at = time.time()
        if self.last_ping is None:
            self.last_ping = time.time()

class SignalingServer:
    """WebRTC signaling server"""
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        
        # Connected peers
        self.peers: Dict[str, ConnectedPeer] = {}
        self.room_peers: Dict[str, Set[str]] = {}
        
        # Server state
        self.running = False
        self.server: Optional[Any] = None
        
        # Statistics
        self.total_connections = 0
        self.active_connections = 0
        self.messages_relayed = 0
        
        # Check dependencies
        self.available = websockets is not None
    
    async def start(self) -> bool:
        """Start signaling server"""
        if not self.available:
            log.error("websockets not available for signaling server")
            return False
        
        try:
            self.server = await websockets.serve(
                self._handle_connection,
                self.host,
                self.port
            )
            
            self.running = True
            log.info(f"Signaling server started on {self.host}:{self.port}")
            return True
            
        except Exception as e:
            log.error(f"Error starting signaling server: {e}")
            return False
    
    async def stop(self):
        """Stop signaling server"""
        self.running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Disconnect all peers
        for peer in list(self.peers.values()):
            try:
                await peer.websocket.close()
            except:
                pass
        
        self.peers.clear()
        self.room_peers.clear()
        
        log.info("Signaling server stopped")
    
    async def _handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new WebSocket connection"""
        try:
            # Wait for peer info
            message = await websocket.recv()
            data = json.loads(message)
            
            if data.get("type") != "peer_info":
                await websocket.close(1003, "Expected peer_info")
                return
            
            # Extract peer information
            peer_id = data.get("peer_id")
            nickname = data.get("nickname", "Unknown")
            fingerprint = data.get("fingerprint", "")
            room = data.get("room", "default")
            capabilities = data.get("capabilities", [])
            
            if not peer_id:
                await websocket.close(1003, "Missing peer_id")
                return
            
            # Check if peer already connected
            if peer_id in self.peers:
                log.warning(f"Peer {peer_id} already connected, disconnecting old connection")
                old_peer = self.peers[peer_id]
                await old_peer.websocket.close()
            
            # Create connected peer
            peer = ConnectedPeer(
                websocket=websocket,
                peer_id=peer_id,
                nickname=nickname,
                fingerprint=fingerprint,
                room=room,
                capabilities=capabilities,
                connected_at=time.time(),
                last_ping=time.time()
            )
            
            # Register peer
            self.peers[peer_id] = peer
            
            # Add to room
            if room not in self.room_peers:
                self.room_peers[room] = set()
            self.room_peers[room].add(peer_id)
            
            self.total_connections += 1
            self.active_connections += 1
            
            log.info(f"Peer {peer_id} ({nickname}) connected to room {room}")
            
            # Send peer list to new peer
            await self._send_peer_list(peer)
            
            # Notify other peers
            await self._broadcast_peer_joined(peer)
            
            # Handle messages
            await self._handle_peer_messages(peer)
            
        except Exception as e:
            log.error(f"Error handling connection: {e}")
        finally:
            # Cleanup
            if peer_id in self.peers:
                await self._cleanup_peer(peer_id)
    
    async def _handle_peer_messages(self, peer: ConnectedPeer):
        """Handle messages from a peer"""
        try:
            async for message in peer.websocket:
                try:
                    data = json.loads(message)
                    await self._handle_message(peer, data)
                except json.JSONDecodeError:
                    log.warning(f"Invalid JSON from peer {peer.peer_id}")
                except Exception as e:
                    log.error(f"Error handling message from {peer.peer_id}: {e}")
        except Exception as e:
            log.info(f"Peer {peer.peer_id} disconnected: {e}")
    
    async def _handle_message(self, sender: ConnectedPeer, data: dict):
        """Handle incoming message"""
        message_type = data.get("type")
        
        if message_type == "signaling":
            await self._handle_signaling_message(sender, data)
        elif message_type == "ping":
            await self._handle_ping(sender)
        elif message_type == "peer_list_request":
            await self._send_peer_list(sender)
        elif message_type == "room_peers_request":
            await self._send_room_peers(sender)
        else:
            log.warning(f"Unknown message type: {message_type}")
    
    async def _handle_signaling_message(self, sender: ConnectedPeer, data: dict):
        """Handle signaling message"""
        target_peer_id = data.get("target_peer_id")
        message_data = data.get("data")
        
        if not target_peer_id or not message_data:
            log.warning(f"Invalid signaling message from {sender.peer_id}")
            return
        
        # Check if target peer exists
        if target_peer_id not in self.peers:
            log.warning(f"Target peer {target_peer_id} not found")
            await self._send_error(sender, f"Peer {target_peer_id} not found")
            return
        
        target_peer = self.peers[target_peer_id]
        
        # Forward signaling message
        forward_data = {
            "type": "signaling",
            "sender_id": sender.peer_id,
            "data": message_data
        }
        
        try:
            await target_peer.websocket.send(json.dumps(forward_data))
            self.messages_relayed += 1
            log.debug(f"Relayed signaling message from {sender.peer_id} to {target_peer_id}")
        except Exception as e:
            log.error(f"Error relaying signaling message: {e}")
            await self._cleanup_peer(target_peer_id)
    
    async def _handle_ping(self, peer: ConnectedPeer):
        """Handle ping message"""
        peer.last_ping = time.time()
        
        # Send pong
        pong_data = {
            "type": "pong",
            "timestamp": time.time()
        }
        
        try:
            await peer.websocket.send(json.dumps(pong_data))
        except Exception as e:
            log.error(f"Error sending pong to {peer.peer_id}: {e}")
            await self._cleanup_peer(peer.peer_id)
    
    async def _send_peer_list(self, peer: ConnectedPeer):
        """Send list of peers in the same room"""
        room_peers = self.room_peers.get(peer.room, set())
        peer_list = []
        
        for peer_id in room_peers:
            if peer_id != peer.peer_id and peer_id in self.peers:
                other_peer = self.peers[peer_id]
                peer_info = {
                    "peer_id": other_peer.peer_id,
                    "nickname": other_peer.nickname,
                    "fingerprint": other_peer.fingerprint,
                    "capabilities": other_peer.capabilities,
                    "connected_at": other_peer.connected_at
                }
                peer_list.append(peer_info)
        
        message = {
            "type": "peer_list",
            "peers": peer_list
        }
        
        try:
            await peer.websocket.send(json.dumps(message))
        except Exception as e:
            log.error(f"Error sending peer list to {peer.peer_id}: {e}")
    
    async def _send_room_peers(self, peer: ConnectedPeer):
        """Send list of all peers in the room"""
        room_peers = self.room_peers.get(peer.room, set())
        peer_list = []
        
        for peer_id in room_peers:
            if peer_id in self.peers:
                other_peer = self.peers[peer_id]
                peer_info = {
                    "peer_id": other_peer.peer_id,
                    "nickname": other_peer.nickname,
                    "fingerprint": other_peer.fingerprint,
                    "capabilities": other_peer.capabilities
                }
                peer_list.append(peer_info)
        
        message = {
            "type": "room_peers",
            "room": peer.room,
            "peers": peer_list
        }
        
        try:
            await peer.websocket.send(json.dumps(message))
        except Exception as e:
            log.error(f"Error sending room peers to {peer.peer_id}: {e}")
    
    async def _broadcast_peer_joined(self, peer: ConnectedPeer):
        """Broadcast that a peer joined"""
        message = {
            "type": "peer_joined",
            "peer": {
                "peer_id": peer.peer_id,
                "nickname": peer.nickname,
                "fingerprint": peer.fingerprint,
                "capabilities": peer.capabilities,
                "connected_at": peer.connected_at
            }
        }
        
        await self._broadcast_to_room(peer.room, message, exclude_peer=peer.peer_id)
    
    async def _broadcast_peer_left(self, peer_id: str, room: str):
        """Broadcast that a peer left"""
        message = {
            "type": "peer_left",
            "peer_id": peer_id,
            "room": room
        }
        
        await self._broadcast_to_room(room, message)
    
    async def _broadcast_to_room(self, room: str, message: dict, exclude_peer: str = None):
        """Broadcast message to all peers in a room"""
        room_peers = self.room_peers.get(room, set())
        
        for peer_id in room_peers:
            if peer_id != exclude_peer and peer_id in self.peers:
                peer = self.peers[peer_id]
                try:
                    await peer.websocket.send(json.dumps(message))
                except Exception as e:
                    log.error(f"Error broadcasting to {peer_id}: {e}")
                    await self._cleanup_peer(peer_id)
    
    async def _send_error(self, peer: ConnectedPeer, error_message: str):
        """Send error message to peer"""
        message = {
            "type": "error",
            "error": error_message
        }
        
        try:
            await peer.websocket.send(json.dumps(message))
        except Exception as e:
            log.error(f"Error sending error to {peer.peer_id}: {e}")
    
    async def _cleanup_peer(self, peer_id: str):
        """Clean up disconnected peer"""
        if peer_id not in self.peers:
            return
        
        peer = self.peers[peer_id]
        room = peer.room
        
        # Remove from peers
        del self.peers[peer_id]
        self.active_connections -= 1
        
        # Remove from room
        if room in self.room_peers:
            self.room_peers[room].discard(peer_id)
            if not self.room_peers[room]:
                del self.room_peers[room]
        
        # Close websocket
        try:
            await peer.websocket.close()
        except:
            pass
        
        # Broadcast peer left
        await self._broadcast_peer_left(peer_id, room)
        
        log.info(f"Peer {peer_id} cleaned up")
    
    async def _cleanup_loop(self):
        """Periodic cleanup of dead connections"""
        while self.running:
            try:
                current_time = time.time()
                dead_peers = []
                
                # Check for dead peers (no ping for 90 seconds)
                for peer_id, peer in self.peers.items():
                    if current_time - peer.last_ping > 90:
                        dead_peers.append(peer_id)
                
                # Clean up dead peers
                for peer_id in dead_peers:
                    log.info(f"Cleaning up dead peer: {peer_id}")
                    await self._cleanup_peer(peer_id)
                
                await asyncio.sleep(30)  # Cleanup every 30 seconds
                
            except Exception as e:
                log.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(30)
    
    def get_stats(self) -> dict:
        """Get server statistics"""
        return {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "messages_relayed": self.messages_relayed,
            "rooms": len(self.room_peers),
            "peers_per_room": {
                room: len(peers) for room, peers in self.room_peers.items()
            }
        }

# Utility functions
def create_signaling_server(host: str = "localhost", port: int = 8765) -> SignalingServer:
    """Create signaling server instance"""
    return SignalingServer(host, port)

def is_signaling_available() -> bool:
    """Check if signaling server is available"""
    return websockets is not None

# Main entry point
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    async def main():
        if not is_signaling_available():
            print("❌ websockets not available")
            return
        
        server = create_signaling_server()
        
        try:
            if await server.start():
                print(f"🚀 Signaling server started on ws://{server.host}:{server.port}")
                
                # Start cleanup loop
                cleanup_task = asyncio.create_task(server._cleanup_loop())
                
                # Keep server running
                try:
                    while server.running:
                        await asyncio.sleep(1)
                        
                        # Print stats every 30 seconds
                        stats = server.get_stats()
                        print(f"📊 Stats: {stats['active_connections']} active, {stats['messages_relayed']} messages")
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
    
    asyncio.run(main())
