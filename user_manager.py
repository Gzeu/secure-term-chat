#!/usr/bin/env python3
"""
User Management System for secure-term-chat
Centralized user profiles, roles, permissions, and audit trail
"""

import asyncio
import time
import json
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

class UserRole(Enum):
    """User roles with hierarchical permissions"""
    GUEST = "guest"
    MEMBER = "member"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

class Permission(Enum):
    """Granular permissions"""
    READ_MESSAGES = "read_messages"
    SEND_MESSAGES = "send_messages"
    MANAGE_ROOMS = "manage_rooms"
    MANAGE_USERS = "manage_users"
    MANAGE_PERMISSIONS = "manage_permissions"
    DELETE_ROOMS = "delete_rooms"
    VIEW_ANALYTICS = "view_analytics"
    MANAGE_SETTINGS = "manage_settings"
    VIEW_AUDIT_LOG = "view_audit_log"
    SYSTEM_ADMIN = "system_admin"

class UserStatus(Enum):
    """User status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    BANNED = "banned"
    PENDING_VERIFICATION = "pending_verification"

@dataclass
class UserProfile:
    """User profile with comprehensive information"""
    user_id: str
    username: str
    email: str
    display_name: str
    avatar_url: str
    bio: str
    created_at: float
    last_login: float
    status: UserStatus
    role: UserRole
    permissions: Set[Permission]
    preferences: Dict[str, Any]
    statistics: Dict[str, Any]
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_login is None:
            self.last_login = time.time()
        if self.permissions is None:
            self.permissions = set()
        if self.preferences is None:
            self.preferences = {}
        if self.statistics is None:
            self.statistics = {}
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserProfile':
        """Create profile from dictionary"""
        return cls(
            user_id=data["user_id"],
            username=data["username"],
            email=data.get("email", ""),
            display_name=data.get("display_name", ""),
            avatar_url=data.get("avatar_url", ""),
            bio=data.get("bio", ""),
            created_at=data.get("created_at", time.time()),
            last_login=data.get("last_login", time.time()),
            status=UserStatus(data.get("status", "active")),
            role=UserRole(data.get("role", UserRole.MEMBER)),
            permissions=set(data.get("permissions", [])),
            preferences=data.get("preferences", {}),
            statistics=data.get("statistics", {}),
            metadata=data.get("metadata", {})
        )

@dataclass
class AuditLogEntry:
    """Audit log entry for compliance tracking"""
    log_id: str
    timestamp: float
    user_id: str
    action: str
    target: str
    details: Dict[str, Any]
    ip_address: str
    user_agent: str
    room_id: str
    success: bool
    error_message: str = ""
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit entry to dictionary"""
        return asdict(self)

class SessionManager:
    """Manages user sessions and authentication"""
    
    def __init__(self):
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout = 3600  # 1 hour
        self.max_sessions_per_user = 5
        self.failed_login_attempts: Dict[str, int] = defaultdict(int)
        self.max_failed_attempts = 5
        self.session_history: deque(maxlen=1000)
    
    async def create_session(self, user_id: str, ip_address: str, user_agent: str) -> Optional[str]:
        """Create new user session"""
        try:
            # Check if user exists and is not banned
            user = self.get_user(user_id)
            if not user or user.status == UserStatus.BANNED:
                return None
            
            # Check failed login attempts
            if self.failed_login_attempts[user_id] >= self.max_failed_attempts:
                return None
            
            # Check session limit
            user_sessions = self.active_sessions.get(user_id, {})
            if len(user_sessions) >= self.max_sessions_per_user:
                return None
            
            # Create session
            session_id = hashlib.sha256(f"{user_id}:{ip_address}:{user_agent}:{time.time()}").hexdigest()
            
            session_data = {
                "user_id": user_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": time.time(),
                "last_activity": time.time(),
                "expires_at": time.time() + self.session_timeout
            }
            
            self.active_sessions[user_id][session_id] = session_data
            self.session_history.append(session_data)
            
            # Update user login info
            user.last_login = time.time()
            user.status = UserStatus.ACTIVE
            self.failed_login_attempts[user_id] = 0
            
            log.info(f"Created session {session_id} for user {user_id}")
            return session_id
            
        except Exception as e:
            log.error(f"Error creating session: {e}")
            return None
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID"""
        return self.active_sessions.get(session_id)
    
    async def validate_session(self, session_id: str, user_id: str) -> bool:
        """Validate session validity"""
        try:
            session = self.get_session(session_id)
            if not session:
                return False
            
            # Check if session exists for user
            if session["user_id"] != user_id:
                return False
            
            # Check if session is expired
            if time.time() > session["expires_at"]:
                return False
            
            # Update last activity
            session["last_activity"] = time.time()
            return True
            
        except Exception as e:
            log.error(f"Error validating session: {e}")
            return False
    
    def invalidate_session(self, session_id: str):
        """Invalidate session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            log.info(f"Invalidated session {session_id}")
    
    def invalidate_user_sessions(self, user_id: str):
        """Invalidate all sessions for user"""
        if user_id in self.active_sessions:
            sessions = list(self.active_sessions[user_id].keys())
            for session_id in sessions:
                del self.active_sessions[session_id]
            log.info(f"Invalidated {len(sessions)} sessions for user {user_id}")
    
    def get_user_sessions(self, user_id: str) -> List[str]:
        """Get all sessions for user"""
        return list(self.active_sessions.get(user_id, {}).keys())
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        current_time = time.time()
        expired_sessions = []
        
        for user_id, sessions in self.active_sessions.items():
            expired_sessions.extend([
                session_id for session_id, session in sessions.items()
                if current_time > session.get("expires_at", 0)
            ])
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
        
        if expired_sessions:
            log.info(f"Cleaned up {len(expired_sessions)} expired sessions")

class PermissionManager:
    """Manages permissions and role hierarchy"""
    
    def __init__(self):
        self.role_hierarchy = {
            UserRole.GUEST: [Permission.READ_MESSAGES],
            UserRole.MEMBER: [
                Permission.READ_MESSAGES,
                Permission.SEND_MESSAGES
            ],
            UserRole.MODERATOR: [
                Permission.READ_MESSAGES,
                Permission.SEND_MESSAGES,
                Permission.KICK_USERS,
                Permission.VIEW_ANALYTICS
            ],
            UserRole.ADMIN: [
                Permission.READ_MESSAGES,
                Permission.SEND_MESSAGES,
                Permission.MANAGE_ROOMS,
                Permission.MANAGE_USERS,
                Permission.MANAGE_PERMISSIONS,
                Permission.VIEW_ANALYTICS,
                Permission.MANAGE_SETTINGS,
                Permission.DELETE_ROOMS
            ],
            UserRole.SUPER_ADMIN: [
                Permission.READ_MESSAGES,
                Permission.SEND_MESSAGES,
                Permission.MANAGE_ROOMS,
                Permission.MANAGE_USERS,
                Permission.MANAGE_PERMISSIONS,
                Permission.VIEW_ANALYTICS,
                Permission.MANAGE_SETTINGS,
                Permission.DELETE_ROOMS,
                Permission.SYSTEM_ADMIN
            ]
        }
        
        self.user_permissions: Dict[str, Set[Permission]] = defaultdict(set)
    
    def get_user_role(self, user_id: str) -> UserRole:
        """Get user's role"""
        # In a real implementation, this would query a database
        return UserRole.MEMBER  # Default role
    
    def has_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if user has permission"""
        user_permissions = self.user_permissions.get(user_id, set())
        return permission in user_permissions
    
    def grant_permission(self, user_id: str, permission: Permission) -> bool:
        """Grant permission to user"""
        if user_id not in self.user_permissions:
            self.user_permissions[user_id] = set()
        
        self.user_permissions[user_id].add(permission)
        return True
    
    def revoke_permission(self, user_id: str, permission: Permission) -> bool:
        """Revoke permission from user"""
        if user_id not in self.user_permissions:
            return False
        
        user_permissions = self.user_permissions[user_id]
        if permission in user_permissions:
            user_permissions.remove(permission)
            return True
        
        return False
    
    def can_perform_action(self, user_id: str, action: str, context: Dict[str, Any] = None) -> bool:
        """Check if user can perform specific action"""
        action_permissions = {
            "read_messages": Permission.READ_MESSAGES,
            "send_messages": Permission.SEND_MESSAGES,
            "manage_rooms": Permission.MANAGE_ROOMS,
            "manage_users": Permission.MANAGE_USERS,
            "manage_permissions": Permission.MANAGE_PERMISSIONS,
            "delete_rooms": Permission.DELETE_ROOMS,
            "view_analytics": Permission.VIEW_ANALYTICS,
            "manage_settings": Permission.MANAGE_SETTINGS,
            "system_admin": Permission.SYSTEM_ADMIN
        }
        
        permission = action_permissions.get(action)
        if permission:
            return self.has_permission(user_id, permission)
        
        return False
    
    def get_user_permissions_summary(self, user_id: str) -> Dict[str, Any]:
        """Get user permissions summary"""
        user_permissions = self.user_permissions.get(user_id, set())
        role = self.get_user_role(user_id)
        
        return {
            "role": role.value,
            "permissions": list(user_permissions),
            "permission_count": len(user_permissions)
        }

class UserManager:
    """Manages all user operations and data"""
    
    def __init__(self):
        self.users: Dict[str, UserProfile] = {}
        self.session_manager = SessionManager()
        self.permission_manager = PermissionManager()
        
        # Statistics
        self.total_users = 0
        self.active_users = 0
        self.total_logins = 0
        failed_logins = 0
        
        # User cache
        self.user_cache: Dict[str, UserProfile] = {}
        self.cache_timeout = 300  # 5 minutes
    
        # Configuration
        self.max_users = 1000
        self.session_timeout = 3600  # 1 hour
        self.password_min_length = 8
        self.require_email_verification = True
        self.two_factor_required = False
    
    async def create_user(self, username: str, email: str, password: str, 
                        display_name: str = "", bio: str = "", 
                        role: UserRole = UserRole.MEMBER,
                        preferences: Dict[str, Any] = None,
                        metadata: Dict[str, Any] = None) -> Tuple[bool, str]:
        """Create new user"""
        try:
            # Check if username exists
            if username in self.users:
                return False, "Username already exists"
            
            # Check email requirements
            if self.require_email_verification:
                if not email or '@' not in email:
                    return False, "Email is required"
            
            # Check password requirements
            if len(password) < self.password_min_length:
                return False, f"Password too short (min {self.password_min_length} characters)"
            
            # Check user limits
            if self.total_users >= self.max_users:
                return False, "User limit reached"
            
            # Create user profile
            user_id = hashlib.sha256(f"{username}{email}{time.time()}").hexdigest()
            
            profile = UserProfile(
                user_id=user_id,
                username=username,
                email=email,
                display_name=display_name or username,
                avatar_url="",
                bio=bio,
                created_at=time.time(),
                last_login=time.time(),
                status=UserStatus.PENDING_VERIFICATION,
                role=role,
                permissions=set(),
                preferences=preferences or {},
                statistics={},
                metadata=metadata or {}
            )
            
            # Store user
            self.users[user_id] = profile
            self.total_users += 1
            
            # Add to cache
            self.user_cache[user_id] = profile
            self.user_cache[user_id]["cached_at"] = time.time()
            
            # Send verification email if required
            if self.require_email_verification:
                await self._send_verification_email(email, username)
            
            log.info(f"Created user: {username} ({user_id})")
            return True, user_id
            
        except Exception as e:
            log.error(f"Error creating user: {e}")
            return False, f"Error: {e}"
    
    async def verify_email(self, token: str) -> bool:
        """Verify email verification token"""
        try:
            # In a real implementation, this would validate the token
            # For now, we'll just accept any token as valid
            return True
        except Exception as e:
            log.error(f"Error verifying email: {e}")
            return False
    
    async def _send_verification_email(self, email: str):
        """Send verification email"""
        # In a real implementation, this would send an email with verification link
        log.info(f"Verification email sent to {email}")
    
    async def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user credentials"""
        try:
            user = self.get_user_by_username(username)
            if not user:
                return False, "User not found"
            
            # Check password (in real implementation, use bcrypt)
            if password != "password":  # Placeholder check
                return False, "Invalid password"
            
            # Update login info
            user.last_login = time.time()
            user.status = UserStatus.ACTIVE
            self.user_cache[user_id]["cached_at"] = time.time()
            
            # Add to session
            session_id = await self.session_manager.create_session(
                user_id, 
                "127.0.0.1",  # IP address
                "Mozilla/5.0"  # User agent
            )
            
            if session_id:
                return True, session_id
            else:
                return False, "Session creation failed"
                
        except Exception as e:
            log.error(f"Error authenticating user: {e}")
            return False, f"Authentication error: {e}"
    
    def get_user_by_id(self, user_id: str) -> Optional[UserProfile]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[UserProfile]:
        """Get user by username"""
        for user in self.users.values():
            if user.username == username:
                return user
        return None
    
    def get_user_rooms(self, user_id: str) -> List[str]:
        """Get rooms user has access to"""
        user = self.get_user_by_id(user_id)
        if not user:
            return []
        
        # In a real implementation, this would query room memberships
        # For now, we'll return empty list
        return []
    
    def update_user_profile(self, user_id: str, **kwargs) -> bool:
        """Update user profile"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return False
            
            # Update fields
            for key, value in kwargs.items():
                if hasattr(user, key) and hasattr(user, key):
                    setattr(user, key, value)
            
            # Update cache
            self.user_cache[user_id]["cached_at"] = time.time()
            
            log.info(f"Updated profile for user {user_id}")
            return True
            
        except Exception as e:
            log.error(f"Error updating user profile: {e}")
            return False
    
    def delete_user(self, user_id: str) -> bool:
        """Delete user account"""
        try:
            if user_id not in self.users:
                return False
            
            # Delete user data
            del self.users[user_id]
            
            # Invalidate sessions
            self.session_manager.invalidate_user_sessions(user_id)
            
            # Remove from cache
            if user_id in self.user_cache:
                del self.user_cache[user_id]
            
            # Update statistics
            self.total_users -= 1
            if user.status == UserStatus.ACTIVE:
                self.active_users -= 1
            
            log.info(f"Deleted user {user_id}")
            return True
            
        except Exception as e:
            log.error(f"Error deleting user: {e}")
            return False
    
    def ban_user(self, user_id: str, reason: str, duration_hours: int = 24) -> bool:
        """Ban user temporarily"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return False
            
            # Update status
            user.status = UserStatus.BANNED
            user.metadata["ban_reason"] = reason
            user.metadata["banned_until"] = time.time() + (duration_hours * 3600)
            
            # Invalidate sessions
            self.session_manager.invalidate_user_sessions(user_id)
            
            log.info(f"Banned user {user_id} for {duration_hours}h: {reason}")
            return True
            
        except Exception as e:
            log.error(f"Error banning user: {e}")
            return False
    
    def unban_user(self, user_id: str) -> bool:
        """Unban user"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return False
            
            if user.status != UserStatus.BANNED:
                return False
            
            # Update status
            user.status = UserStatus.ACTIVE
            user.metadata.pop("ban_reason", None)
            user.metadata.pop("banned_until", None)
            
            # Invalidate sessions
            self.session_manager.invalidate_user_sessions(user_id)
            
            log.info(f"Unbanned user {user_id}")
            return True
            
        except Exception as e:
            log.error(f"Error unbanning user: {e}")
            return False
    
    def promote_user(self, user_id: str, new_role: UserRole) -> bool:
        """Promote user to higher role"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return False
            
            old_role = user.role
            user.role = new_role
            
            # Check if promotion is allowed
            role_hierarchy = [
                UserRole.MEMBER,
                UserRole.MODERATOR,
                UserRole.ADMIN,
                UserRole.SUPER_ADMIN
            ]
            
            old_index = role_hierarchy.index(old_role)
            new_index = role_hierarchy.index(new_role)
            
            if new_index <= old_index:
                return False
            
            # Update permissions
            user.permissions.update(self.permission_manager.role_hierarchy[new_role])
            
            log.info(f"Promoted {user_id} from {old_role.value} to {new_role.value}")
            return True
            
        except Exception as e:
            log.error(f"Error promoting user: {e}")
            return False
    
    def demote_user(self, user_id: str, new_role: UserRole) -> bool:
        """Demote user to lower role"""
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return False
            
            old_role = user.role
            user.role = new_role
            
            # Check if demotion is allowed
            role_hierarchy = [
                UserRole.SUPER_ADMIN,
                UserRole.ADMIN,
                UserRole.MODERATOR,
                UserRole.MEMBER,
                UserRole.GUEST
            ]
            
            old_index = role_hierarchy.index(old_role)
            new_index = role_hierarchy.index(new_role)
            
            if new_index >= old_index:
                return False
            
            # Update permissions
            user.permissions.update(self.permission_manager.role_hierarchy[new_role])
            
            log.info(f"Demoted {user_id} from {old_role.value} to {new_role.value}")
            return True
            
        except Exception as e:
            log.error(f"Error demoting user: {e}")
            return False
    
    def get_user_statistics(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive user statistics"""
        user = self.get_user_by_id(user_id)
        if not user:
            return {}
        
        return {
            "joined": user.created_at,
            "last_login": user.last_login,
            "status": user.status.value,
            "role": user.role.value,
            "permission_count": len(user.permissions),
            "message_count": user.statistics.get("message_count", 0),
            "file_count": user.statistics.get("file_count", 0),
            "room_count": len(self.get_user_rooms(user_id)),
            "session_count": len(self.session_manager.get_user_sessions(user_id))
        }
    
    def get_global_statistics(self) -> Dict[str, Any]:
        """Get global user statistics"""
        active_users = len([u for u in self.users.values() if u.status == UserStatus.ACTIVE])
        total_logins = self.total_logins + self.failed_logins
        
        return {
            "total_users": self.total_users,
            "active_users": active_users,
            "total_logins": total_logins,
            "failed_logins": failed_logins,
            "success_rate": (total_logins / (total_logins + failed_logins)) * 100 if (total_logins + failed_logins) > 0 else 0,
            "cache_size": len(self.user_cache)
        }

# Utility functions
def create_user_manager() -> UserManager:
    """Create user manager instance"""
    return UserManager()

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    async def test_user_manager():
        """Test user management system"""
        manager = create_user_manager()
        
        # Create test users
        success1, user1_id = await manager.create_user(
            "alice", "alice@example.com", "secure123456", 
            "Alice Smith", "alice@example.com",
            role=UserRole.MEMBER
        )
        
        success2, user2_id = await manager.create_user(
            "bob", "bob@example.com", "secure456",
            "Bob Johnson", "bob@example.com",
            role=UserRole.MODER
        )
        
        success3, user3_id = await manager.create_user(
            "charlie", "charlie@example.com", "secure456",
            "Charlie Brown", "charlie@example.com",
            role=UserRole.ADMIN
        )
        
        if success1 and user1_id:
            print(f"✅ Created user: alice ({user1_id})")
        
        if success2 and user2_id:
            print(f"✅ Created user: bob ({user2_id})")
        
        if success3 and user3_id:
            print(f"✅ Created user: charlie ({user3_id})")
        
        # Test authentication
        alice_auth = await manager.authenticate_user("alice", "secure456")
        print(f"🔐 Alice auth: {alice_auth}")
        
        # Test permissions
        can_send = manager.can_perform_action(user1, "send_messages", {})
        print(f"Alice can send messages: {can_send}")
        
        # Test promotion
        success = manager.promote_user(user2, UserRole.ADMIN)
        print(f"Bob promoted to admin: {success}")
        
        # Get statistics
        stats = manager.get_global_statistics()
        print(f"📊 Global stats: {stats}")
        
        print("✅ User manager test completed")
    
    asyncio.run(test_user_manager())
