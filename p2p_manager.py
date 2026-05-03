#!/usr/bin/env python3
"""
P2P WebRTC Manager for secure-term-chat
Direct peer-to-peer communication with relay fallback
"""

import asyncio
import json
import time
import logging
from typing import Optional, Dict, List, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, RTCIceCandidate
    from aiortc.contrib.signaling import object_to_string, string_to_object
    from aiortc import MediaStreamTrack
    from aiortc.rtp import RtpPacket
    import websockets
except ImportError:
    RTCPeerConnection = None
    RTCSessionDescription = None
    RTCIceCandidate = None
    websockets = None

log = logging.getLogger(__name__)

class P2PState(Enum):
    """P2P connection state"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"
    FALLBACK = "fallback"

class P2PMessageType(Enum):
    """P2P message types"""
    SIGNAL_OFFER = "signal_offer"
    SIGNAL_ANSWER = "signal_answer"
    SIGNAL_ICE = "signal_ice"
    DATA_MESSAGE = "data_message"
    PING = "ping"
    PONG = "pong"
    PEER_INFO = "peer_info"
    CONNECTION_REQUEST = "connection_request"
    CONNECTION_ACCEPT = "connection_accept"
    CONNECTION_REJECT = "connection_reject"

@dataclass
class PeerInfo:
    """Peer information"""
    peer_id: str
    nickname: str
    fingerprint: str
    room: str
    capabilities: List[str]
    last_seen: float
    p2p_capable: bool = True
    
    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = time.time()

@dataclass
class P2PMessage:
    """P2P message structure"""
    message_type: P2PMessageType
    sender_id: str
    receiver_id: str
    data: Any
    timestamp: float
    room: str = ""
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

class P2PConnection:
    """Individual P2P connection to a peer"""
    
    def __init__(self, peer_info: PeerInfo, local_peer_id: str):
        self.peer_info = peer_info
        self.local_peer_id = local_peer_id
        self.state = P2PState.DISCONNECTED
        self.pc: Optional[RTCPeerConnection] = None
        self.channel: Optional[any] = None  # RTCDataChannel
        self.signaling_queue: asyncio.Queue = asyncio.Queue()
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.last_activity = time.time()
        self.connection_attempts = 0
        self.max_attempts = 3
        
    async def create_connection(self) -> bool:
        """Create WebRTC peer connection"""
        if RTCPeerConnection is None:
            log.error("aiortc not available for P2P connections")
            return False
            
        try:
            self.pc = RTCPeerConnection()
            self.state = P2PState.CONNECTING
            
            # Setup data channel
            self.channel = self.pc.createDataChannel("chat", ordered=True)
            self.channel.on("message")(self._on_message)
            self.channel.on("open")(self._on_channel_open)
            self.channel.on("close")(self._on_channel_close)
            
            # Setup ICE candidates
            self.pc.on("icecandidate")(self._on_ice_candidate)
            self.pc.on("iceconnectionstatechange")(self._on_ice_connection_state_change)
            
            return True
            
        except Exception as e:
            log.error(f"Error creating P2P connection: {e}")
            self.state = P2PState.FAILED
            return False
    
    async def create_offer(self) -> Optional[RTCSessionDescription]:
        """Create WebRTC offer"""
        if not self.pc:
            return None
            
        try:
            offer = await self.pc.createOffer()
            await self.pc.setLocalDescription(offer)
            return offer
        except Exception as e:
            log.error(f"Error creating offer: {e}")
            return None
    
    async def create_answer(self, offer: RTCSessionDescription) -> Optional[RTCSessionDescription]:
        """Create WebRTC answer"""
        if not self.pc:
            return None
            
        try:
            await self.pc.setRemoteDescription(offer)
            answer = await self.pc.createAnswer()
            await self.pc.setLocalDescription(answer)
            return answer
        except Exception as e:
            log.error(f"Error creating answer: {e}")
            return None
    
    async def add_ice_candidate(self, candidate: RTCIceCandidate) -> bool:
        """Add ICE candidate"""
        if not self.pc:
            return False
            
        try:
            await self.pc.addIceCandidate(candidate)
            return True
        except Exception as e:
            log.error(f"Error adding ICE candidate: {e}")
            return False
    
    async def send_message(self, message: str) -> bool:
        """Send message through P2P connection"""
        if not self.channel or self.channel.readyState != "open":
            return False
            
        try:
            self.channel.send(message)
            self.last_activity = time.time()
            return True
        except Exception as e:
            log.error(f"Error sending P2P message: {e}")
            return False
    
    async def close(self):
        """Close P2P connection"""
        if self.channel:
            self.channel.close()
        if self.pc:
            await self.pc.close()
        self.state = P2PState.DISCONNECTED
    
    def _on_message(self, message):
        """Handle incoming message"""
        try:
            data = json.loads(message)
            p2p_msg = P2PMessage(**data)
            asyncio.create_task(self.message_queue.put(p2p_msg))
            self.last_activity = time.time()
        except Exception as e:
            log.error(f"Error parsing P2P message: {e}")
    
    def _on_channel_open(self):
        """Data channel opened"""
        self.state = P2PState.CONNECTED
        log.info(f"P2P channel opened to {self.peer_info.peer_id}")
    
    def _on_channel_close(self):
        """Data channel closed"""
        self.state = P2PState.DISCONNECTED
        log.info(f"P2P channel closed to {self.peer_info.peer_id}")
    
    def _on_ice_candidate(self, candidate):
        """ICE candidate generated"""
        asyncio.create_task(self.signaling_queue.put(candidate))
    
    def _on_ice_connection_state_change(self, state):
        """ICE connection state changed"""
        log.info(f"ICE connection state to {self.peer_info.peer_id}: {state}")
        if state == "failed":
            self.state = P2PState.FAILED
        elif state == "connected":
            self.state = P2PState.CONNECTED

class P2PManager:
    """P2P WebRTC communication manager"""
    
    def __init__(self, local_peer_id: str, nickname: str, fingerprint: str, room: str):
        self.local_peer_id = local_peer_id
        self.nickname = nickname
        self.fingerprint = fingerprint
        self.room = room
        
        # P2P connections
        self.connections: Dict[str, P2PConnection] = {}
        self.peers: Dict[str, PeerInfo] = {}
        
        # Signaling
        self.signaling_server: Optional[str] = None
        self.signaling_websocket: Optional[any] = None
        
        # State
        self.state = P2PState.DISCONNECTED
        self.p2p_enabled = True
        self.auto_fallback = True
        
        # Callbacks
        self.on_peer_connected: Optional[Callable] = None
        self.on_peer_disconnected: Optional[Callable] = None
        self.on_message_received: Optional[Callable] = None
        
        # Tasks
        self.signaling_task: Optional[asyncio.Task] = None
        self.heartbeat_task: Optional[asyncio.Task] = None
        
        # Check dependencies
        self.p2p_available = RTCPeerConnection is not None and websockets is not None
        
    async def start(self, signaling_server: str = None) -> bool:
        """Start P2P manager"""
        if not self.p2p_available:
            log.warning("P2P not available (missing dependencies)")
            return False
            
        self.signaling_server = signaling_server
        self.state = P2PState.CONNECTING
        
        try:
            # Start signaling if server provided
            if signaling_server:
                await self._connect_signaling_server()
            
            # Start heartbeat
            self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            self.state = P2PState.CONNECTED
            log.info("P2P manager started successfully")
            return True
            
        except Exception as e:
            log.error(f"Error starting P2P manager: {e}")
            self.state = P2PState.FAILED
            return False
    
    async def stop(self):
        """Stop P2P manager"""
        self.state = P2PState.DISCONNECTED
        
        # Close all connections
        for connection in self.connections.values():
            await connection.close()
        self.connections.clear()
        
        # Close signaling
        if self.signaling_websocket:
            await self.signaling_websocket.close()
        
        # Cancel tasks
        if self.signaling_task:
            self.signaling_task.cancel()
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        
        log.info("P2P manager stopped")
    
    async def connect_to_peer(self, peer_info: PeerInfo) -> bool:
        """Connect to a peer"""
        if not self.p2p_available or not peer_info.p2p_capable:
            return False
            
        if peer_info.peer_id in self.connections:
            return True  # Already connected
        
        try:
            # Create connection
            connection = P2PConnection(peer_info, self.local_peer_id)
            
            if not await connection.create_connection():
                return False
            
            # Create offer
            offer = await connection.create_offer()
            if not offer:
                return False
            
            # Send offer through signaling
            await self._send_signaling_message(peer_info.peer_id, {
                "type": "offer",
                "offer": object_to_string(offer)
            })
            
            self.connections[peer_info.peer_id] = connection
            self.peers[peer_info.peer_id] = peer_info
            
            log.info(f"Initiated P2P connection to {peer_info.peer_id}")
            return True
            
        except Exception as e:
            log.error(f"Error connecting to peer {peer_info.peer_id}: {e}")
            return False
    
    async def handle_signaling_message(self, sender_id: str, message_data: dict) -> bool:
        """Handle incoming signaling message"""
        try:
            message_type = message_data.get("type")
            
            if message_type == "offer":
                await self._handle_offer(sender_id, message_data)
            elif message_type == "answer":
                await self._handle_answer(sender_id, message_data)
            elif message_type == "ice":
                await self._handle_ice_candidate(sender_id, message_data)
            else:
                log.warning(f"Unknown signaling message type: {message_type}")
                return False
                
            return True
            
        except Exception as e:
            log.error(f"Error handling signaling message: {e}")
            return False
    
    async def send_message_to_peer(self, peer_id: str, message: str) -> bool:
        """Send message to specific peer"""
        if peer_id not in self.connections:
            return False
        
        connection = self.connections[peer_id]
        return await connection.send_message(message)
    
    async def broadcast_message(self, message: str) -> int:
        """Broadcast message to all connected peers"""
        sent_count = 0
        for connection in self.connections.values():
            if connection.state == P2PState.CONNECTED:
                if await connection.send_message(message):
                    sent_count += 1
        return sent_count
    
    def get_connected_peers(self) -> List[str]:
        """Get list of connected peer IDs"""
        return [
            peer_id for peer_id, conn in self.connections.items()
            if conn.state == P2PState.CONNECTED
        ]
    
    def get_peer_info(self, peer_id: str) -> Optional[PeerInfo]:
        """Get peer information"""
        return self.peers.get(peer_id)
    
    async def _connect_signaling_server(self):
        """Connect to signaling server"""
        if not self.signaling_server or not websockets:
            return
        
        try:
            self.signaling_websocket = await websockets.connect(self.signaling_server)
            
            # Send peer info
            await self.signaling_websocket.send(json.dumps({
                "type": "peer_info",
                "peer_id": self.local_peer_id,
                "nickname": self.nickname,
                "fingerprint": self.fingerprint,
                "room": self.room,
                "capabilities": ["p2p", "encryption"]
            }))
            
            # Start signaling loop
            self.signaling_task = asyncio.create_task(self._signaling_loop())
            
        except Exception as e:
            log.error(f"Error connecting to signaling server: {e}")
    
    async def _signaling_loop(self):
        """Signaling message loop"""
        if not self.signaling_websocket:
            return
        
        try:
            async for message in self.signaling_websocket:
                try:
                    data = json.loads(message)
                    await self.handle_signaling_message(data.get("sender_id"), data.get("data"))
                except Exception as e:
                    log.error(f"Error processing signaling message: {e}")
        except Exception as e:
            log.error(f"Signaling loop error: {e}")
    
    async def _send_signaling_message(self, target_peer_id: str, data: dict):
        """Send signaling message"""
        if not self.signaling_websocket:
            return
        
        try:
            message = {
                "type": "signaling",
                "sender_id": self.local_peer_id,
                "target_peer_id": target_peer_id,
                "data": data
            }
            await self.signaling_websocket.send(json.dumps(message))
        except Exception as e:
            log.error(f"Error sending signaling message: {e}")
    
    async def _handle_offer(self, sender_id: str, message_data: dict):
        """Handle WebRTC offer"""
        if sender_id in self.connections:
            return  # Already connected
        
        try:
            # Get peer info
            peer_info = self.peers.get(sender_id)
            if not peer_info:
                return
            
            # Create connection
            connection = P2PConnection(peer_info, self.local_peer_id)
            
            if not await connection.create_connection():
                return
            
            # Parse offer
            offer_str = message_data.get("offer")
            offer = string_to_object(offer_str)
            
            # Create answer
            answer = await connection.create_answer(offer)
            if not answer:
                return
            
            # Send answer
            await self._send_signaling_message(sender_id, {
                "type": "answer",
                "answer": object_to_string(answer)
            })
            
            self.connections[sender_id] = connection
            
            log.info(f"Accepted P2P connection from {sender_id}")
            
        except Exception as e:
            log.error(f"Error handling offer from {sender_id}: {e}")
    
    async def _handle_answer(self, sender_id: str, message_data: dict):
        """Handle WebRTC answer"""
        if sender_id not in self.connections:
            return
        
        try:
            connection = self.connections[sender_id]
            
            # Parse answer
            answer_str = message_data.get("answer")
            answer = string_to_object(answer_str)
            
            # Set remote description
            await connection.pc.setRemoteDescription(answer)
            
            log.info(f"Received P2P answer from {sender_id}")
            
        except Exception as e:
            log.error(f"Error handling answer from {sender_id}: {e}")
    
    async def _handle_ice_candidate(self, sender_id: str, message_data: dict):
        """Handle ICE candidate"""
        if sender_id not in self.connections:
            return
        
        try:
            connection = self.connections[sender_id]
            
            # Parse candidate
            candidate_str = message_data.get("candidate")
            candidate = string_to_object(candidate_str)
            
            # Add candidate
            await connection.add_ice_candidate(candidate)
            
        except Exception as e:
            log.error(f"Error handling ICE candidate from {sender_id}: {e}")
    
    async def _heartbeat_loop(self):
        """Heartbeat loop for connection maintenance"""
        while self.state == P2PState.CONNECTED:
            try:
                # Check connection health
                current_time = time.time()
                dead_peers = []
                
                for peer_id, connection in self.connections.items():
                    # Check if connection is dead (no activity for 60 seconds)
                    if current_time - connection.last_activity > 60:
                        dead_peers.append(peer_id)
                
                # Clean up dead connections
                for peer_id in dead_peers:
                    await self.connections[peer_id].close()
                    del self.connections[peer_id]
                    if self.on_peer_disconnected:
                        self.on_peer_disconnected(peer_id)
                
                # Send ping to connected peers
                ping_message = json.dumps({
                    "type": "ping",
                    "timestamp": current_time
                })
                
                for connection in self.connections.values():
                    if connection.state == P2PState.CONNECTED:
                        await connection.send_message(ping_message)
                
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
                
            except Exception as e:
                log.error(f"Heartbeat loop error: {e}")
                await asyncio.sleep(30)

# Utility functions
def create_p2p_manager(local_peer_id: str, nickname: str, fingerprint: str, room: str) -> P2PManager:
    """Create P2P manager instance"""
    return P2PManager(local_peer_id, nickname, fingerprint, room)

def is_p2p_available() -> bool:
    """Check if P2P is available"""
    return RTCPeerConnection is not None and websockets is not None

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    # Test P2P manager
    manager = P2PManager("test_peer", "TestUser", "fp123", "test_room")
    
    async def test_p2p():
        if await manager.start():
            print("P2P manager started successfully")
            
            # Test peer info
            peer = PeerInfo(
                peer_id="test_peer_2",
                nickname="TestUser2",
                fingerprint="fp456",
                room="test_room",
                capabilities=["p2p", "encryption"]
            )
            
            # Test connection
            if await manager.connect_to_peer(peer):
                print("P2P connection initiated")
            
            await asyncio.sleep(5)
            await manager.stop()
        else:
            print("P2P manager failed to start")
    
    asyncio.run(test_p2p())
