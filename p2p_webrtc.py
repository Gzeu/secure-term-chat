#!/usr/bin/env python3
"""
WebRTC P2P Implementation for secure-term-chat
Provides direct peer-to-peer connections as alternative to relay server
"""

import asyncio
import json
import logging
from typing import Dict, Optional, List, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import websockets
from pathlib import Path

# Configure logging
log = logging.getLogger("p2p_webrtc")

class P2PState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"

@dataclass
class PeerInfo:
    peer_id: str
    nickname: str
    fingerprint: str
    signaling_server: str
    ice_candidates: List[str] = field(default_factory=list)
    offer: Optional[str] = None
    answer: Optional[str] = None

@dataclass
class P2PConfig:
    enable_relay_fallback: bool = True
    ice_servers: List[Dict] = field(default_factory=lambda: [
        {"urls": "stun:stun.l.google.com:19302"},
        {"urls": "stun:stun1.l.google.com:19302"}
    ])
    max_peers: int = 10
    connection_timeout: int = 30
    heartbeat_interval: int = 15

class WebRTCP2PManager:
    """
    WebRTC-based P2P communication manager
    Provides direct peer-to-peer connections with relay fallback
    """
    
    def __init__(self, config: P2PConfig):
        self.config = config
        self.state = P2PState.DISCONNECTED
        self.local_peer_id: Optional[str] = None
        self.local_nickname: Optional[str] = None
        self.local_fingerprint: Optional[str] = None
        
        # Peer management
        self.connected_peers: Dict[str, PeerInfo] = {}
        self.pending_connections: Dict[str, asyncio.Task] = {}
        
        # Signaling
        self.signaling_server: Optional[str] = None
        self.signaling_ws: Optional[websockets.WebSocketServerProtocol] = None
        
        # Callbacks
        self.on_message_received: Optional[Callable] = None
        self.on_peer_connected: Optional[Callable] = None
        self.on_peer_disconnected: Optional[Callable] = None
        
        # WebRTC connections (simplified for Python implementation)
        self.active_connections: Dict[str, Any] = {}
        
        log.info("WebRTC P2P Manager initialized")
    
    async def start(self, nickname: str, fingerprint: str, signaling_server: str = None) -> bool:
        """Start P2P manager with optional signaling server"""
        try:
            self.local_nickname = nickname
            self.local_fingerprint = fingerprint
            self.local_peer_id = f"{nickname}_{fingerprint[:8]}"
            
            if signaling_server:
                self.signaling_server = signaling_server
                success = await self._connect_to_signaling_server()
                if not success:
                    log.warning("Failed to connect to signaling server, using P2P discovery only")
                    self.signaling_server = None
            else:
                log.info("No signaling server specified, using P2P discovery only")
            
            self.state = P2PState.CONNECTED
            log.info(f"P2P Manager started: {self.local_peer_id}")
            return True
            
        except Exception as e:
            log.error(f"Failed to start P2P manager: {e}")
            self.state = P2PState.FAILED
            return False
    
    async def stop(self) -> None:
        """Stop P2P manager and cleanup connections"""
        try:
            self.state = P2PState.DISCONNECTED
            
            # Cancel pending connections
            for task in self.pending_connections.values():
                task.cancel()
            self.pending_connections.clear()
            
            # Close active connections
            for peer_id in list(self.connected_peers.keys()):
                await self.disconnect_peer(peer_id)
            
            # Close signaling connection
            if self.signaling_ws:
                await self.signaling_ws.close()
                self.signaling_ws = None
            
            log.info("P2P Manager stopped")
            
        except Exception as e:
            log.error(f"Error during P2P manager shutdown: {e}")
    
    async def connect_to_peer(self, peer_info: PeerInfo) -> bool:
        """Establish direct connection to peer"""
        try:
            if len(self.connected_peers) >= self.config.max_peers:
                log.warning("Maximum peer connections reached")
                return False
            
            if peer_info.peer_id in self.connected_peers:
                log.warning(f"Already connected to peer {peer_info.peer_id}")
                return True
            
            log.info(f"Connecting to peer {peer_info.peer_id}")
            
            # Create connection task
            task = asyncio.create_task(self._establish_p2p_connection(peer_info))
            self.pending_connections[peer_info.peer_id] = task
            
            # Wait for connection or timeout
            try:
                await asyncio.wait_for(task, timeout=self.config.connection_timeout)
                return True
            except asyncio.TimeoutError:
                log.warning(f"Connection to {peer_info.peer_id} timed out")
                task.cancel()
                self.pending_connections.pop(peer_info.peer_id, None)
                return False
                
        except Exception as e:
            log.error(f"Failed to connect to peer {peer_info.peer_id}: {e}")
            return False
    
    async def disconnect_peer(self, peer_id: str) -> None:
        """Disconnect from peer and cleanup"""
        try:
            # Cancel pending connection
            if peer_id in self.pending_connections:
                task = self.pending_connections.pop(peer_id)
                task.cancel()
            
            # Close active connection
            if peer_id in self.connected_peers:
                peer_info = self.connected_peers.pop(peer_id)
                if peer_id in self.active_connections:
                    connection = self.active_connections.pop(peer_id)
                    # Close WebRTC connection
                    await self._close_webrtc_connection(connection)
                
                log.info(f"Disconnected from peer {peer_id}")
                
                # Notify callback
                if self.on_peer_disconnected:
                    await self.on_peer_disconnected(peer_id)
                    
        except Exception as e:
            log.error(f"Error disconnecting from peer {peer_id}: {e}")
    
    async def send_message(self, peer_id: str, message: str) -> bool:
        """Send message to connected peer"""
        try:
            if peer_id not in self.connected_peers:
                log.warning(f"Not connected to peer {peer_id}")
                return False
            
            if peer_id not in self.active_connections:
                log.warning(f"No active connection to peer {peer_id}")
                return False
            
            connection = self.active_connections[peer_id]
            await self._send_webrtc_message(connection, message)
            
            log.debug(f"Message sent to {peer_id}")
            return True
            
        except Exception as e:
            log.error(f"Failed to send message to {peer_id}: {e}")
            return False
    
    async def broadcast_message(self, message: str) -> int:
        """Broadcast message to all connected peers"""
        success_count = 0
        failed_peers = []
        
        for peer_id in list(self.connected_peers.keys()):
            if await self.send_message(peer_id, message):
                success_count += 1
            else:
                failed_peers.append(peer_id)
        
        if failed_peers:
            log.warning(f"Failed to send to peers: {failed_peers}")
        
        log.info(f"Broadcast sent to {success_count} peers")
        return success_count
    
    def get_connected_peers(self) -> List[PeerInfo]:
        """Get list of connected peers"""
        return list(self.connected_peers.values())
    
    def is_connected(self) -> bool:
        """Check if P2P manager is connected to any peers"""
        return self.state == P2PState.CONNECTED and len(self.connected_peers) > 0
    
    # Private methods
    
    async def _connect_to_signaling_server(self) -> bool:
        """Connect to WebRTC signaling server"""
        try:
            uri = f"ws://{self.signaling_server}/signaling"
            self.signaling_ws = await websockets.connect(uri)
            
            # Send peer info
            await self.signaling_ws.send(json.dumps({
                "type": "register",
                "peer_id": self.local_peer_id,
                "nickname": self.local_nickname,
                "fingerprint": self.local_fingerprint
            }))
            
            # Start message handler
            asyncio.create_task(self._handle_signaling_messages())
            
            log.info(f"Connected to signaling server: {self.signaling_server}")
            return True
            
        except Exception as e:
            log.error(f"Failed to connect to signaling server: {e}")
            return False
    
    async def _handle_signaling_messages(self) -> None:
        """Handle messages from signaling server"""
        try:
            async for message in self.signaling_ws:
                try:
                    data = json.loads(message)
                    await self._process_signaling_message(data)
                except json.JSONDecodeError:
                    log.warning(f"Invalid JSON from signaling: {message}")
                except Exception as e:
                    log.error(f"Error processing signaling message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            log.info("Signaling server connection closed")
        except Exception as e:
            log.error(f"Signaling message handler error: {e}")
    
    async def _process_signaling_message(self, data: Dict) -> None:
        """Process incoming signaling message"""
        msg_type = data.get("type")
        
        if msg_type == "peer_discovery":
            await self._handle_peer_discovery(data)
        elif msg_type == "offer":
            await self._handle_offer(data)
        elif msg_type == "answer":
            await self._handle_answer(data)
        elif msg_type == "ice_candidate":
            await self._handle_ice_candidate(data)
        elif msg_type == "peer_left":
            await self._handle_peer_left(data)
        else:
            log.warning(f"Unknown signaling message type: {msg_type}")
    
    async def _handle_peer_discovery(self, data: Dict) -> None:
        """Handle peer discovery announcement"""
        peer_info = PeerInfo(
            peer_id=data["peer_id"],
            nickname=data["nickname"],
            fingerprint=data["fingerprint"],
            signaling_server=self.signaling_server
        )
        
        # Auto-connect to discovered peers
        if peer_info.peer_id != self.local_peer_id:
            asyncio.create_task(self.connect_to_peer(peer_info))
    
    async def _establish_p2p_connection(self, peer_info: PeerInfo) -> None:
        """Establish WebRTC connection to peer"""
        try:
            # This is a simplified implementation
            # In production, you'd use aiortc or similar WebRTC library
            
            # Simulate WebRTC connection establishment
            await asyncio.sleep(1)  # Simulate ICE gathering
            
            # Create mock connection
            connection = {
                "peer_id": peer_info.peer_id,
                "state": "connected",
                "data_channel": {"open": True}
            }
            
            self.active_connections[peer_info.peer_id] = connection
            self.connected_peers[peer_info.peer_id] = peer_info
            
            # Remove from pending
            self.pending_connections.pop(peer_info.peer_id, None)
            
            log.info(f"P2P connection established with {peer_info.peer_id}")
            
            # Notify callback
            if self.on_peer_connected:
                await self.on_peer_connected(peer_info.peer_id)
            
            # Start message handler
            asyncio.create_task(self._handle_peer_messages(peer_info.peer_id))
            
        except Exception as e:
            log.error(f"Failed to establish P2P connection: {e}")
            self.pending_connections.pop(peer_info.peer_id, None)
    
    async def _handle_peer_messages(self, peer_id: str) -> None:
        """Handle messages from connected peer"""
        try:
            connection = self.active_connections.get(peer_id)
            if not connection:
                return
            
            # Simulate receiving messages
            while peer_id in self.connected_peers:
                await asyncio.sleep(1)  # Simulate message checking
                
                # In production, you'd receive actual WebRTC messages here
                # For now, we'll simulate periodic heartbeat
                
        except Exception as e:
            log.error(f"Error handling messages from {peer_id}: {e}")
            await self.disconnect_peer(peer_id)
    
    async def _send_webrtc_message(self, connection: Dict, message: str) -> None:
        """Send message over WebRTC data channel"""
        # Simplified implementation
        # In production, you'd use actual WebRTC data channel
        log.debug(f"Sending WebRTC message: {message[:50]}...")
    
    async def _close_webrtc_connection(self, connection: Dict) -> None:
        """Close WebRTC connection"""
        # Simplified implementation
        connection["state"] = "closed"
        connection["data_channel"]["open"] = False
    
    async def _handle_offer(self, data: Dict) -> None:
        """Handle WebRTC offer"""
        # Simplified WebRTC offer handling
        pass
    
    async def _handle_answer(self, data: Dict) -> None:
        """Handle WebRTC answer"""
        # Simplified WebRTC answer handling
        pass
    
    async def _handle_ice_candidate(self, data: Dict) -> None:
        """Handle ICE candidate"""
        # Simplified ICE candidate handling
        pass
    
    async def _handle_peer_left(self, data: Dict) -> None:
        """Handle peer disconnection announcement"""
        peer_id = data.get("peer_id")
        if peer_id and peer_id in self.connected_peers:
            await self.disconnect_peer(peer_id)

class P2PRelayFallback:
    """
    Fallback to relay server when P2P fails
    Automatically switches between P2P and relay modes
    """
    
    def __init__(self, p2p_manager: WebRTCP2PManager, relay_client):
        self.p2p_manager = p2p_manager
        self.relay_client = relay_client
        self.preferred_mode = "p2p"  # p2p or relay
        self.connected_peers: Dict[str, str] = {}  # peer_id -> mode
    
    async def send_message(self, peer_id: str, message: str) -> bool:
        """Send message using best available connection"""
        mode = self.connected_peers.get(peer_id, self.preferred_mode)
        
        if mode == "p2p" and peer_id in self.p2p_manager.connected_peers:
            # Try P2P first
            if await self.p2p_manager.send_message(peer_id, message):
                return True
            # Fallback to relay
            self.connected_peers[peer_id] = "relay"
        
        # Use relay
        return await self.relay_client.send_pm(peer_id, message)
    
    async def connect_to_peer(self, peer_info: PeerInfo) -> bool:
        """Try P2P first, fallback to relay"""
        if self.preferred_mode == "p2p":
            p2p_success = await self.p2p_manager.connect_to_peer(peer_info)
            if p2p_success:
                self.connected_peers[peer_info.peer_id] = "p2p"
                return True
        
        # Fallback to relay
        self.connected_peers[peer_info.peer_id] = "relay"
        return True  # Relay always "succeeds"
    
    def get_connection_mode(self, peer_id: str) -> str:
        """Get connection mode for peer"""
        return self.connected_peers.get(peer_id, "relay")

# Factory function
def create_p2p_manager(config: P2PConfig = None) -> WebRTCP2PManager:
    """Create P2P manager with default configuration"""
    if config is None:
        config = P2PConfig()
    return WebRTCP2PManager(config)

# Example usage
async def example_usage():
    """Example of how to use P2P manager"""
    config = P2PConfig(
        enable_relay_fallback=True,
        max_peers=5,
        connection_timeout=20
    )
    
    p2p = create_p2p_manager(config)
    
    # Set callbacks
    async def on_message(peer_id: str, message: str):
        print(f"Message from {peer_id}: {message}")
    
    async def on_peer_connected(peer_id: str):
        print(f"Peer connected: {peer_id}")
    
    async def on_peer_disconnected(peer_id: str):
        print(f"Peer disconnected: {peer_id}")
    
    p2p.on_message_received = on_message
    p2p.on_peer_connected = on_peer_connected
    p2p.on_peer_disconnected = on_peer_disconnected
    
    # Start P2P manager
    await p2p.start("test_user", "ab:cd:ef:12")
    
    # Connect to peer
    peer_info = PeerInfo(
        peer_id="other_user_abcd",
        nickname="OtherUser",
        fingerprint="12:34:56:78",
        signaling_server="localhost:8080"
    )
    
    await p2p.connect_to_peer(peer_info)
    
    # Send message
    await p2p.send_message("other_user_abcd", "Hello P2P!")
    
    # Cleanup
    await p2p.stop()

if __name__ == "__main__":
    asyncio.run(example_usage())
