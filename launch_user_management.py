#!/usr/bin/env python3
"""
Launch script for User Management System
Easy entry point for advanced user management with roles and permissions
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from user_management_ui import create_user_management_ui

def main():
    """Launch the user management system"""
    print("👥 Starting User Management System...")
    print("🔐 Advanced user management with roles and permissions")
    print("📊 Real-time user statistics and analytics")
    print("🔍 Comprehensive audit trail and compliance")
    print("─" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        app = create_user_management_ui()
        app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error starting user management: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
