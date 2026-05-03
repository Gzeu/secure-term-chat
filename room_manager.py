#!/usr/bin/env python3
"""
Room Management System for secure-term-chat
Advanced multi-room management with permissions and analytics
"""

import asyncio
import time
import json
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque

log = logging.getLogger(__name__)

class RoomType(Enum):
    """Types of rooms"""
    PUBLIC = "public"
    PRIVATE = "private"
    RESTRICTED = "restricted"
    TEMPORARY = "temporary"
    PERSISTENT = "persistent"

class UserRole(Enum):
    """User roles in rooms"""
    OWNER = "owner"
    ADMIN = "admin"
    MODERATOR = "moderator"
    MEMBER = "member"
    GUEST = "guest"
    BANNED = "banned"

class RoomPermission(Enum):
    """Room permissions"""
    READ_MESSAGES = "read_messages"
    SEND_MESSAGES = "send_messages"
    INVITE_USERS = "invite_users"
    KICK_USERS = "kick_users"
    BAN_USERS = "ban_users"
    MANAGE_PERMISSIONS = "manage_permissions"
    DELETE_ROOM = "delete_room"
    VIEW_ANALYTICS = "view_analytics"
    MANAGE_SETTINGS = "manage_settings"

@dataclass
class RoomSettings:
    """Room configuration settings"""
    max_members: int = 100
    allow_guests: bool = True
    require_approval: bool = False
    auto_delete: bool = False
    delete_after_hours: int = 24
    enable_file_sharing: bool = True
    max_file_size_mb: int = 10
    enable_voice_chat: bool = False
    enable_video_chat: bool = False
    message_retention_days: int = 30
    enable_analytics: bool = True
    is_encrypted: bool = True
    require_2fa: bool = False
    allow_screen_sharing: bool = False
    enable_polls: bool = True
    enable_reactions: bool = True

@dataclass
class RoomAnalytics:
    """Room analytics data"""
    room_id: str
    created_at: float
    total_messages: int
    active_users: int
    peak_users: int
    avg_message_length: float
    messages_per_hour: float
    file_transfers: int
    total_file_size_mb: float
    most_active_user: str
    last_activity: float
    uptime_hours: float
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_activity is None:
            self.last_activity = time.time()

@dataclass
class Room:
    """Room definition with all properties"""
    room_id: str
    name: str
    description: str
    room_type: RoomType
    owner_id: str
    created_at: float
    settings: RoomSettings
    analytics: RoomAnalytics
    tags: Set[str] = None
    members: Dict[str, UserRole] = None
    banned_users: Set[str] = None
    invited_users: Set[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = set()
        if self.members is None:
            self.members = {self.owner_id: UserRole.OWNER}
        if self.banned_users is None:
            self.banned_users = set()
        if self.invited_users is None:
            self.invited_users = set()

@dataclass
class UserRoomProfile:
    """User's profile in a specific room"""
    user_id: str
    room_id: str
    role: UserRole
    joined_at: float
    last_seen: float
    message_count: int
    file_uploads: int
    warnings: int
    is_muted: bool = False
    mute_expires: float = 0
    is_banned: bool = False
    ban_expires: float = 0
    custom_permissions: Set[RoomPermission] = None
    
    def __post_init__(self):
        if self.custom_permissions is None:
            self.custom_permissions = set()
        if self.joined_at is None:
            self.joined_at = time.time()
        if self.last_seen is None:
            self.last_seen = time.time()

class PermissionManager:
    """Manages room permissions and roles"""
    
    def __init__(self):
        self.role_permissions: Dict[UserRole, Set[RoomPermission]] = {
            UserRole.OWNER: {
                RoomPermission.READ_MESSAGES,
                RoomPermission.SEND_MESSAGES,
                RoomPermission.INVITE_USERS,
                RoomPermission.KICK_USERS,
                RoomPermission.BAN_USERS,
                RoomPermission.MANAGE_PERMISSIONS,
                RoomPermission.DELETE_ROOM,
                RoomPermission.VIEW_ANALYTICS,
                RoomPermission.MANAGE_SETTINGS
            },
            UserRole.ADMIN: {
                RoomPermission.READ_MESSAGES,
                RoomPermission.SEND_MESSAGES,
                RoomPermission.INVITE_USERS,
                RoomPermission.KICK_USERS,
                RoomPermission.VIEW_ANALYTICS,
                RoomPermission.MANAGE_SETTINGS
            },
            UserRole.MODERATOR: {
                RoomPermission.READ_MESSAGES,
                RoomPermission.SEND_MESSAGES,
                RoomPermission.KICK_USERS,
                RoomPermission.VIEW_ANALYTICS
            },
            UserRole.MEMBER: {
                RoomPermission.READ_MESSAGES,
                RoomPermission.SEND_MESSAGES
            },
            UserRole.GUEST: {
                RoomPermission.READ_MESSAGES
            },
            UserRole.BANNED: set()
        }
    
    def has_permission(self, user_id: str, room: Room, permission: RoomPermission) -> bool:
        """Check if user has permission in room"""
        if user_id not in room.members:
            return False
        
        role = room.members[user_id]
        
        # Check custom permissions first
        user_profile = self.get_user_profile(user_id, room.room_id)
        if user_profile and permission in user_profile.custom_permissions:
            return True
        
        # Check role-based permissions
        return permission in self.role_permissions.get(role, set())
    
    def grant_permission(self, user_id: str, room: Room, permission: RoomPermission) -> bool:
        """Grant custom permission to user"""
        if user_id not in room.members:
            return False
        
        user_profile = self.get_user_profile(user_id, room.room_id)
        if user_profile:
            user_profile.custom_permissions.add(permission)
            return True
        return False
    
    def revoke_permission(self, user_id: str, room: Room, permission: RoomPermission) -> bool:
        """Revoke custom permission from user"""
        if user_id not in room.members:
            return False
        
        user_profile = self.get_user_profile(user_id, room.room_id)
        if user_profile and permission in user_profile.custom_permissions:
            user_profile.custom_permissions.remove(permission)
            return True
        return False
    
    def get_user_profile(self, user_id: str, room_id: str) -> Optional[UserRoomProfile]:
        """Get user's profile in room (would be stored in database)"""
        # In a real implementation, this would query a database
        return None
    
    def can_perform_action(self, user_id: str, room: Room, action: str) -> bool:
        """Check if user can perform specific action"""
        action_permissions = {
            "send_message": RoomPermission.SEND_MESSAGES,
            "invite_user": RoomPermission.INVITE_USERS,
            "kick_user": RoomPermission.KICK_USERS,
            "ban_user": RoomPermission.BAN_USERS,
            "delete_room": RoomPermission.DELETE_ROOM,
            "view_analytics": RoomPermission.VIEW_ANALYTICS,
            "manage_settings": RoomPermission.MANAGE_SETTINGS
        }
        
        permission = action_permissions.get(action)
        if permission:
            return self.has_permission(user_id, room, permission)
        return False

class RoomManager:
    """Manages all rooms and their operations"""
    
    def __init__(self):
        self.rooms: Dict[str, Room] = {}
        self.user_profiles: Dict[str, Dict[str, UserRoomProfile]] = defaultdict(dict)
        self.permission_manager = PermissionManager()
        self.room_counter = 0
        
        # Analytics
        self.global_analytics = {
            "total_rooms": 0,
            "total_users": 0,
            "total_messages": 0,
            "active_rooms": 0,
            "peak_concurrent_users": 0
        }
    
    async def create_room(self, name: str, description: str, room_type: RoomType, 
                         owner_id: str, settings: RoomSettings = None) -> Optional[Room]:
        """Create a new room"""
        try:
            # Generate unique room ID
            self.room_counter += 1
            room_id = f"room_{self.room_counter:06d}"
            
            # Validate room name
            if not name or len(name) > 64:
                return None
            
            # Check if user can create more rooms
            user_rooms = [r for r in self.rooms.values() if r.owner_id == owner_id]
            max_rooms = 10  # Default limit
            
            if len(user_rooms) >= max_rooms:
                return None
            
            # Create room
            room = Room(
                room_id=room_id,
                name=name,
                description=description,
                room_type=room_type,
                owner_id=owner_id,
                created_at=time.time(),
                settings=settings or RoomSettings(),
                analytics=RoomAnalytics(
                    room_id=room_id,
                    created_at=time.time(),
                    total_messages=0,
                    active_users=0,
                    peak_users=0,
                    avg_message_length=0,
                    messages_per_hour=0,
                    file_transfers=0,
                    total_file_size_mb=0,
                    most_active_user="",
                    last_activity=time.time(),
                    uptime_hours=0
                )
            )
            
            # Store room
            self.rooms[room_id] = room
            
            # Create owner profile
            owner_profile = UserRoomProfile(
                user_id=owner_id,
                room_id=room_id,
                role=UserRole.OWNER,
                joined_at=time.time(),
                last_seen=time.time(),
                message_count=0,
                file_uploads=0,
                warnings=0
            )
            
            self.user_profiles[owner_id][room_id] = owner_profile
            
            # Update analytics
            self.global_analytics["total_rooms"] += 1
            self.global_analytics["total_users"] += 1
            
            log.info(f"Created room {room_id}: {name} by {owner_id}")
            return room
            
        except Exception as e:
            log.error(f"Error creating room: {e}")
            return None
    
    async def delete_room(self, room_id: str, user_id: str) -> bool:
        """Delete a room"""
        try:
            if room_id not in self.rooms:
                return False
            
            room = self.rooms[room_id]
            
            # Check permissions
            if not self.permission_manager.can_perform_action(user_id, room, "delete_room"):
                return False
            
            # Remove all user profiles
            for profile_user_id, profiles in self.user_profiles.items():
                if room_id in profiles:
                    del profiles[room_id]
            
            # Remove room
            del self.rooms[room_id]
            
            # Update analytics
            self.global_analytics["total_rooms"] -= 1
            
            log.info(f"Deleted room {room_id} by {user_id}")
            return True
            
        except Exception as e:
            log.error(f"Error deleting room: {e}")
            return False
    
    async def join_room(self, room_id: str, user_id: str, invite_code: str = None) -> bool:
        """Join a room"""
        try:
            if room_id not in self.rooms:
                return False
            
            room = self.rooms[room_id]
            
            # Check if user is banned
            if user_id in room.banned_users:
                return False
            
            # Check if already a member
            if user_id in room.members:
                return True
            
            # Check room type requirements
            if room.room_type == RoomType.PRIVATE:
                if user_id not in room.invited_users:
                    return False
            elif room.room_type == RoomType.RESTRICTED:
                if not invite_code or invite_code != self._generate_invite_code(room):
                    return False
            
            # Check room capacity
            if len(room.members) >= room.settings.max_members:
                return False
            
            # Add user as member
            room.members[user_id] = UserRole.MEMBER
            
            # Create user profile
            user_profile = UserRoomProfile(
                user_id=user_id,
                room_id=room_id,
                role=UserRole.MEMBER,
                joined_at=time.time(),
                last_seen=time.time(),
                message_count=0,
                file_uploads=0,
                warnings=0
            )
            
            self.user_profiles[user_id][room_id] = user_profile
            
            # Update room analytics
            room.analytics.active_users = len(room.members)
            room.analytics.peak_users = max(room.analytics.peak_users, len(room.members))
            
            log.info(f"User {user_id} joined room {room_id}")
            return True
            
        except Exception as e:
            log.error(f"Error joining room: {e}")
            return False
    
    async def leave_room(self, room_id: str, user_id: str) -> bool:
        """Leave a room"""
        try:
            if room_id not in self.rooms:
                return False
            
            room = self.rooms[room_id]
            
            if user_id not in room.members:
                return False
            
            # Remove from room
            del room.members[user_id]
            
            # Remove user profile
            if room_id in self.user_profiles[user_id]:
                del self.user_profiles[user_id][room_id]
            
            # Update analytics
            room.analytics.active_users = len(room.members)
            
            # If room is empty and temporary, delete it
            if room.room_type == RoomType.TEMPORARY and len(room.members) == 0:
                await self.delete_room(room_id, room.owner_id)
            
            log.info(f"User {user_id} left room {room_id}")
            return True
            
        except Exception as e:
            log.error(f"Error leaving room: {e}")
            return False
    
    async def invite_user(self, room_id: str, inviter_id: str, target_user_id: str) -> bool:
        """Invite user to room"""
        try:
            if room_id not in self.rooms:
                return False
            
            room = self.rooms[room_id]
            
            # Check permissions
            if not self.permission_manager.can_perform_action(inviter_id, room, "invite_user"):
                return False
            
            # Add to invited users
            room.invited_users.add(target_user_id)
            
            log.info(f"User {inviter_id} invited {target_user_id} to room {room_id}")
            return True
            
        except Exception as e:
            log.error(f"Error inviting user: {e}")
            return False
    
    async def kick_user(self, room_id: str, kicker_id: str, target_user_id: str, reason: str = "") -> bool:
        """Kick user from room"""
        try:
            if room_id not in self.rooms:
                return False
            
            room = self.rooms[room_id]
            
            # Check permissions
            if not self.permission_manager.can_perform_action(kicker_id, room, "kick_user"):
                return False
            
            # Cannot kick owner
            if target_user_id == room.owner_id:
                return False
            
            # Remove user
            await self.leave_room(room_id, target_user_id)
            
            # Add to invited users (can rejoin if invited)
            room.invited_users.add(target_user_id)
            
            log.info(f"User {kicker_id} kicked {target_user_id} from room {room_id}: {reason}")
            return True
            
        except Exception as e:
            log.error(f"Error kicking user: {e}")
            return False
    
    async def ban_user(self, room_id: str, banner_id: str, target_user_id: str, 
                      duration_hours: int = 24, reason: str = "") -> bool:
        """Ban user from room"""
        try:
            if room_id not in self.rooms:
                return False
            
            room = self.rooms[room_id]
            
            # Check permissions
            if not self.permission_manager.can_perform_action(banner_id, room, "ban_user"):
                return False
            
            # Cannot ban owner
            if target_user_id == room.owner_id:
                return False
            
            # Remove from room
            await self.leave_room(room_id, target_user_id)
            
            # Add to banned users
            room.banned_users.add(target_user_id)
            
            # Update user profile
            if target_user_id in self.user_profiles and room_id in self.user_profiles[target_user_id]:
                profile = self.user_profiles[target_user_id][room_id]
                profile.is_banned = True
                profile.ban_expires = time.time() + (duration_hours * 3600)
            
            log.info(f"User {banner_id} banned {target_user_id} from room {room_id} for {duration_hours}h: {reason}")
            return True
            
        except Exception as e:
            log.error(f"Error banning user: {e}")
            return False
    
    async def update_room_settings(self, room_id: str, user_id: str, settings: RoomSettings) -> bool:
        """Update room settings"""
        try:
            if room_id not in self.rooms:
                return False
            
            room = self.rooms[room_id]
            
            # Check permissions
            if not self.permission_manager.can_perform_action(user_id, room, "manage_settings"):
                return False
            
            # Update settings
            room.settings = settings
            
            log.info(f"User {user_id} updated settings for room {room_id}")
            return True
            
        except Exception as e:
            log.error(f"Error updating room settings: {e}")
            return False
    
    def get_user_rooms(self, user_id: str) -> List[Room]:
        """Get all rooms user is member of"""
        user_rooms = []
        for room in self.rooms.values():
            if user_id in room.members:
                user_rooms.append(room)
        return user_rooms
    
    def get_room_analytics(self, room_id: str) -> Optional[RoomAnalytics]:
        """Get room analytics"""
        if room_id in self.rooms:
            return self.rooms[room_id].analytics
        return None
    
    def update_room_analytics(self, room_id: str, message_count: int = 0, 
                             file_size_mb: float = 0, user_id: str = None):
        """Update room analytics"""
        if room_id not in self.rooms:
            return
        
        room = self.rooms[room_id]
        analytics = room.analytics
        
        # Update message count
        analytics.total_messages += message_count
        analytics.last_activity = time.time()
        
        # Update file transfers
        if file_size_mb > 0:
            analytics.file_transfers += 1
            analytics.total_file_size_mb += file_size_mb
        
        # Update most active user
        if user_id:
            if user_id in self.user_profiles and room_id in self.user_profiles[user_id]:
                profile = self.user_profiles[user_id][room_id]
                profile.message_count += message_count
                profile.file_uploads += 1 if file_size_mb > 0 else 0
                profile.last_seen = time.time()
                
                # Check if this is now the most active user
                if profile.message_count > analytics.total_messages / len(room.members):
                    analytics.most_active_user = user_id
        
        # Calculate uptime
        analytics.uptime_hours = (time.time() - analytics.created_at) / 3600
        
        # Calculate messages per hour
        if analytics.uptime_hours > 0:
            analytics.messages_per_hour = analytics.total_messages / analytics.uptime_hours
    
    def _generate_invite_code(self, room: Room) -> str:
        """Generate invite code for room"""
        import hashlib
        data = f"{room.room_id}:{room.created_at}:{room.owner_id}"
        return hashlib.md5(data.encode()).hexdigest()[:8].upper()
    
    def get_global_analytics(self) -> Dict[str, Any]:
        """Get global analytics"""
        # Update active rooms count
        active_rooms = 0
        total_messages = 0
        total_users = 0
        
        for room in self.rooms.values():
            if room.analytics.last_activity > time.time() - 3600:  # Active in last hour
                active_rooms += 1
            total_messages += room.analytics.total_messages
            total_users += len(room.members)
        
        self.global_analytics.update({
            "active_rooms": active_rooms,
            "total_messages": total_messages,
            "total_users": total_users
        })
        
        return self.global_analytics.copy()

# Utility functions
def create_room_manager() -> RoomManager:
    """Create room manager instance"""
    return RoomManager()

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    async def test_room_manager():
        """Test room management system"""
        manager = create_room_manager()
        
        # Create a room
        settings = RoomSettings(
            max_members=50,
            allow_guests=False,
            enable_file_sharing=True,
            max_file_size_mb=20
        )
        
        room = await manager.create_room(
            name="Test Room",
            description="A test room for demonstration",
            room_type=RoomType.PRIVATE,
            owner_id="user123",
            settings=settings
        )
        
        if room:
            print(f"✅ Created room: {room.name} ({room.room_id})")
            
            # Join room
            success = await manager.join_room(room.room_id, "user456")
            print(f"👥 User joined: {success}")
            
            # Get user rooms
            user_rooms = manager.get_user_rooms("user123")
            print(f"📋 User rooms: {len(user_rooms)}")
            
            # Update analytics
            manager.update_room_analytics(room.room_id, message_count=5, user_id="user123")
            
            # Get analytics
            analytics = manager.get_room_analytics(room.room_id)
            print(f"📊 Room messages: {analytics.total_messages}")
            
            # Global analytics
            global_stats = manager.get_global_analytics()
            print(f"🌐 Global stats: {global_stats}")
        
        print("✅ Room manager test completed")
    
    asyncio.run(test_room_manager())
