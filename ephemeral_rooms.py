#!/usr/bin/env python3
"""
Ephemeral Rooms and Disappearing Messages for secure-term-chat
Provides temporary rooms and self-destructing messages with secure wiping
"""

import asyncio
import time
import hashlib
import secrets
import logging
from typing import Dict, Optional, List, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

# Configure logging
log = logging.getLogger("ephemeral_rooms")

class RoomType(Enum):
    PERMANENT = "permanent"
    EPHEMERAL = "ephemeral"
    AUTO_DELETE = "auto_delete"

class MessageTTL(Enum):
    IMMEDIATE = 0      # Delete immediately after reading
    SHORT = 300        # 5 minutes
    MEDIUM = 3600      # 1 hour
    LONG = 86400       # 24 hours
    WEEK = 604800      # 1 week
    CUSTOM = "custom"

@dataclass
class EphemeralMessage:
    """Message with automatic deletion"""
    message_id: str
    content: bytes
    sender: str
    timestamp: float
    ttl: int  # Time to live in seconds
    room_id: str
    read_count: int = 0
    max_reads: int = 1
    created_at: float = field(default_factory=time.time)
    deleted: bool = False
    
    def is_expired(self) -> bool:
        """Check if message has expired"""
        if self.deleted:
            return True
        if self.ttl == MessageTTL.IMMEDIATE.value and self.read_count > 0:
            return True
        if self.read_count >= self.max_reads:
            return True
        return time.time() > (self.created_at + self.ttl)
    
    def get_remaining_time(self) -> int:
        """Get remaining time in seconds"""
        if self.deleted:
            return 0
        elapsed = time.time() - self.created_at
        return max(0, self.ttl - int(elapsed))
    
    def get_remaining_reads(self) -> int:
        """Get remaining read count"""
        return max(0, self.max_reads - self.read_count)

@dataclass
class EphemeralRoom:
    """Room with automatic deletion"""
    room_id: str
    room_type: RoomType
    creator: str
    created_at: float = field(default_factory=time.time)
    ttl: int = 3600  # Room TTL in seconds
    max_members: int = 10
    auto_delete_when_empty: bool = True
    deleted: bool = False
    members: Set[str] = field(default_factory=set)
    message_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if room should be deleted"""
        if self.deleted:
            return True
        if self.room_type == RoomType.PERMANENT:
            return False
        if self.room_type == RoomType.AUTO_DELETE and len(self.members) == 0:
            return True
        return time.time() > (self.created_at + self.ttl)
    
    def get_remaining_time(self) -> int:
        """Get remaining room time in seconds"""
        if self.deleted or self.room_type == RoomType.PERMANENT:
            return -1
        elapsed = time.time() - self.created_at
        return max(0, self.ttl - int(elapsed))

class EphemeralRoomManager:
    """
    Manager for ephemeral rooms and disappearing messages
    Provides secure wiping and automatic cleanup
    """
    
    def __init__(self, cleanup_interval: int = 60):
        self.cleanup_interval = cleanup_interval
        self.rooms: Dict[str, EphemeralRoom] = {}
        self.messages: Dict[str, EphemeralMessage] = {}
        self.user_rooms: Dict[str, Set[str]] = {}  # user -> room_ids
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Callbacks
        self.on_room_deleted: Optional[Callable] = None
        self.on_message_deleted: Optional[Callable] = None
        
        log.info("Ephemeral Room Manager initialized")
    
    async def start(self) -> None:
        """Start the ephemeral room manager"""
        if self._running:
            return
        
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("Ephemeral Room Manager started")
    
    async def stop(self) -> None:
        """Stop the ephemeral room manager and cleanup"""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        
        # Cleanup all rooms and messages
        await self.cleanup_all()
        
        log.info("Ephemeral Room Manager stopped")
    
    async def create_room(
        self, 
        creator: str, 
        room_type: RoomType = RoomType.EPHEMERAL,
        ttl: int = 3600,
        max_members: int = 10,
        auto_delete_when_empty: bool = True
    ) -> str:
        """Create a new ephemeral room"""
        room_id = self._generate_room_id()
        
        room = EphemeralRoom(
            room_id=room_id,
            room_type=room_type,
            creator=creator,
            ttl=ttl,
            max_members=max_members,
            auto_delete_when_empty=auto_delete_when_empty
        )
        
        self.rooms[room_id] = room
        self.user_rooms[creator] = self.user_rooms.get(creator, set())
        self.user_rooms[creator].add(room_id)
        
        log.info(f"Created {room_type.value} room {room_id} by {creator}")
        return room_id
    
    async def join_room(self, user: str, room_id: str) -> bool:
        """Join an ephemeral room"""
        if room_id not in self.rooms:
            log.warning(f"Room {room_id} not found")
            return False
        
        room = self.rooms[room_id]
        
        if room.deleted or room.is_expired():
            log.warning(f"Room {room_id} is expired or deleted")
            return False
        
        if len(room.members) >= room.max_members:
            log.warning(f"Room {room_id} is full")
            return False
        
        room.members.add(user)
        self.user_rooms[user] = self.user_rooms.get(user, set())
        self.user_rooms[user].add(room_id)
        
        log.info(f"User {user} joined room {room_id}")
        return True
    
    async def leave_room(self, user: str, room_id: str) -> None:
        """Leave an ephemeral room"""
        if room_id not in self.rooms:
            return
        
        room = self.rooms[room_id]
        room.members.discard(user)
        
        # Remove from user's room list
        if user in self.user_rooms:
            self.user_rooms[user].discard(room_id)
            if not self.user_rooms[user]:
                del self.user_rooms[user]
        
        # Check if room should be auto-deleted
        if room.auto_delete_when_empty and len(room.members) == 0:
            await self.delete_room(room_id)
        
        log.info(f"User {user} left room {room_id}")
    
    async def add_message(
        self,
        room_id: str,
        sender: str,
        content: bytes,
        ttl: int = 3600,
        max_reads: int = 1
    ) -> str:
        """Add a disappearing message to a room"""
        if room_id not in self.rooms:
            raise ValueError(f"Room {room_id} not found")
        
        room = self.rooms[room_id]
        if room.deleted or room.is_expired():
            raise ValueError(f"Room {room_id} is expired or deleted")
        
        message_id = self._generate_message_id()
        message = EphemeralMessage(
            message_id=message_id,
            content=content,
            sender=sender,
            ttl=ttl,
            max_reads=max_reads,
            room_id=room_id
        )
        
        self.messages[message_id] = message
        room.message_count += 1
        
        log.debug(f"Added message {message_id} to room {room_id} (TTL: {ttl}s)")
        return message_id
    
    async def get_message(self, message_id: str, reader: str) -> Optional[bytes]:
        """Get a disappearing message (marks as read)"""
        if message_id not in self.messages:
            return None
        
        message = self.messages[message_id]
        
        if message.deleted or message.is_expired():
            return None
        
        # Mark as read
        message.read_count += 1
        
        # Check if message should be deleted immediately
        if message.is_expired():
            await self.delete_message(message_id)
            return None
        
        log.debug(f"Message {message_id} read by {reader}")
        return message.content
    
    async def delete_message(self, message_id: str) -> bool:
        """Delete a message with secure wiping"""
        if message_id not in self.messages:
            return False
        
        message = self.messages[message_id]
        
        if message.deleted:
            return False
        
        # Secure wipe the content
        await self._secure_wipe(message.content)
        message.deleted = True
        
        # Remove from storage
        del self.messages[message_id]
        
        # Update room message count
        if message.room_id in self.rooms:
            self.rooms[message.room_id].message_count -= 1
        
        log.info(f"Message {message_id} securely deleted")
        
        # Notify callback
        if self.on_message_deleted:
            await self.on_message_deleted(message_id)
        
        return True
    
    async def delete_room(self, room_id: str) -> bool:
        """Delete an ephemeral room and all its messages"""
        if room_id not in self.rooms:
            return False
        
        room = self.rooms[room_id]
        
        if room.deleted:
            return False
        
        # Delete all messages in the room
        message_ids_to_delete = [
            msg_id for msg_id, msg in self.messages.items()
            if msg.room_id == room_id
        ]
        
        for message_id in message_ids_to_delete:
            await self.delete_message(message_id)
        
        # Remove room from all users
        for user in room.members:
            if user in self.user_rooms:
                self.user_rooms[user].discard(room_id)
        
        # Remove room
        del self.rooms[room_id]
        
        log.info(f"Room {room_id} deleted with {len(message_ids_to_delete)} messages")
        
        # Notify callback
        if self.on_room_deleted:
            await self.on_room_deleted(room_id)
        
        return True
    
    def get_room_info(self, room_id: str) -> Optional[Dict]:
        """Get information about a room"""
        if room_id not in self.rooms:
            return None
        
        room = self.rooms[room_id]
        return {
            "room_id": room.room_id,
            "room_type": room.room_type.value,
            "creator": room.creator,
            "created_at": room.created_at,
            "ttl": room.ttl,
            "remaining_time": room.get_remaining_time(),
            "max_members": room.max_members,
            "current_members": len(room.members),
            "auto_delete_when_empty": room.auto_delete_when_empty,
            "message_count": room.message_count,
            "deleted": room.deleted
        }
    
    def get_message_info(self, message_id: str) -> Optional[Dict]:
        """Get information about a message"""
        if message_id not in self.messages:
            return None
        
        message = self.messages[message_id]
        return {
            "message_id": message.message_id,
            "sender": message.sender,
            "created_at": message.created_at,
            "ttl": message.ttl,
            "remaining_time": message.get_remaining_time(),
            "read_count": message.read_count,
            "max_reads": message.get_remaining_reads(),
            "deleted": message.deleted
        }
    
    def get_user_rooms(self, user: str) -> List[str]:
        """Get all rooms for a user"""
        return list(self.user_rooms.get(user, set()))
    
    async def cleanup_all(self) -> None:
        """Cleanup all expired rooms and messages"""
        # Delete expired messages
        expired_messages = [
            msg_id for msg_id, msg in self.messages.items()
            if msg.is_expired()
        ]
        
        for message_id in expired_messages:
            await self.delete_message(message_id)
        
        # Delete expired rooms
        expired_rooms = [
            room_id for room_id, room in self.rooms.items()
            if room.is_expired()
        ]
        
        for room_id in expired_rooms:
            await self.delete_room(room_id)
        
        log.info(f"Cleanup: {len(expired_messages)} messages, {len(expired_rooms)} rooms deleted")
    
    # Private methods
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop"""
        while self._running:
            try:
                await self.cleanup_all()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(5)
    
    async def _secure_wipe(self, data: bytearray) -> None:
        """Securely wipe sensitive data"""
        try:
            # Multiple pass wiping
            for _ in range(3):
                for i in range(len(data)):
                    data[i] = secrets.randbelow(256)
            
            # Final wipe with zeros
            for i in range(len(data)):
                data[i] = 0
                
        except Exception as e:
            log.error(f"Error during secure wipe: {e}")
    
    def _generate_room_id(self) -> str:
        """Generate unique room ID"""
        return f"ephemeral_{secrets.token_hex(16)}"
    
    def _generate_message_id(self) -> str:
        """Generate unique message ID"""
        return f"msg_{secrets.token_hex(16)}_{int(time.time())}"

class DisappearingMessageHandler:
    """
    Handler for disappearing messages with advanced features
    """
    
    def __init__(self, room_manager: EphemeralRoomManager):
        self.room_manager = room_manager
        
        # Default TTL settings
        self.default_ttls = {
            "immediate": MessageTTL.IMMEDIATE.value,
            "short": MessageTTL.SHORT.value,
            "medium": MessageTTL.MEDIUM.value,
            "long": MessageTTL.LONG.value,
            "week": MessageTTL.WEEK.value
        }
    
    async def send_disappearing_message(
        self,
        room_id: str,
        sender: str,
        content: str,
        ttl: str = "medium",
        max_reads: int = 1
    ) -> str:
        """Send a disappearing message"""
        ttl_seconds = self.default_ttls.get(ttl, MessageTTL.MEDIUM.value)
        
        content_bytes = content.encode('utf-8')
        
        message_id = await self.room_manager.add_message(
            room_id=room_id,
            sender=sender,
            content=content_bytes,
            ttl=ttl_seconds,
            max_reads=max_reads
        )
        
        log.info(f"Disappearing message sent: {message_id} (TTL: {ttl})")
        return message_id
    
    async def create_ephemeral_room(
        self,
        creator: str,
        room_name: str = "",
        duration: str = "medium",
        max_members: int = 10
    ) -> str:
        """Create an ephemeral room"""
        duration_map = {
            "short": 300,      # 5 minutes
            "medium": 3600,    # 1 hour
            "long": 86400,     # 24 hours
            "week": 604800     # 1 week
        }
        
        ttl = duration_map.get(duration, 3600)
        
        room_id = await self.room_manager.create_room(
            creator=creator,
            room_type=RoomType.EPHEMERAL,
            ttl=ttl,
            max_members=max_members,
            auto_delete_when_empty=True
        )
        
        log.info(f"Ephemeral room created: {room_id} (Duration: {duration})")
        return room_id
    
    async def create_auto_delete_room(
        self,
        creator: str,
        max_members: int = 5
    ) -> str:
        """Create an auto-delete room (deletes when empty)"""
        room_id = await self.room_manager.create_room(
            creator=creator,
            room_type=RoomType.AUTO_DELETE,
            ttl=86400,  # 24 hour fallback
            max_members=max_members,
            auto_delete_when_empty=True
        )
        
        log.info(f"Auto-delete room created: {room_id}")
        return room_id
    
    def get_room_statistics(self) -> Dict:
        """Get statistics about ephemeral rooms and messages"""
        total_rooms = len(self.room_manager.rooms)
        total_messages = len(self.room_manager.messages)
        
        room_types = {}
        for room in self.room_manager.rooms.values():
            room_type = room.room_type.value
            room_types[room_type] = room_types.get(room_type, 0) + 1
        
        return {
            "total_rooms": total_rooms,
            "total_messages": total_messages,
            "room_types": room_types,
            "active_users": len(self.room_manager.user_rooms)
        }

# Factory functions
def create_ephemeral_manager(cleanup_interval: int = 60) -> EphemeralRoomManager:
    """Create ephemeral room manager"""
    return EphemeralRoomManager(cleanup_interval)

def create_disappearing_handler(room_manager: EphemeralRoomManager) -> DisappearingMessageHandler:
    """Create disappearing message handler"""
    return DisappearingMessageHandler(room_manager)

# Example usage
async def example_usage():
    """Example of ephemeral rooms and disappearing messages"""
    manager = create_ephemeral_manager()
    handler = create_disappearing_handler(manager)
    
    await manager.start()
    
    try:
        # Create ephemeral room
        room_id = await handler.create_ephemeral_room(
            creator="alice",
            room_name="secret-chat",
            duration="short",  # 5 minutes
            max_members=5
        )
        
        # Join room
        await manager.join_room("alice", room_id)
        await manager.join_room("bob", room_id)
        
        # Send disappearing message
        message_id = await handler.send_disappearing_message(
            room_id=room_id,
            sender="alice",
            content="This message will disappear in 5 minutes",
            ttl="short",
            max_reads=1
        )
        
        # Read message
        content = await manager.get_message(message_id, "bob")
        print(f"Bob read: {content.decode() if content else 'None'}")
        
        # Check room info
        room_info = manager.get_room_info(room_id)
        print(f"Room info: {room_info}")
        
        # Wait for cleanup
        await asyncio.sleep(10)
        
    finally:
        await manager.stop()

if __name__ == "__main__":
    asyncio.run(example_usage())
