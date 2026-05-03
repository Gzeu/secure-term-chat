#!/usr/bin/env python3
"""
Launch script for Multi-room Management UI
Easy entry point for advanced room management
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from multi_room_ui import create_multi_room_ui

def main():
    """Launch the multi-room management UI"""
    print("🏠 Starting Multi-room Management UI...")
    print("👥 Advanced room management with permissions and analytics")
    print("🔒 Secure room creation and member management")
    print("📊 Real-time room analytics and statistics")
    print("─" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        app = create_multi_room_ui()
        app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error starting multi-room UI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
