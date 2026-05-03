#!/usr/bin/env python3
"""
Launch script for Enhanced File Transfer System
Easy entry point for advanced file sharing with security and optimization
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from file_transfer_ui import create_file_transfer_ui

def main():
    """Launch the file transfer system"""
    print("📁 Starting Enhanced File Transfer System...")
    print("🔒 Secure file sharing with compression and encryption")
    print("📊 Real-time progress tracking and management")
    print("🔍 Virus scanning and content validation")
    print("─" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        app = create_file_transfer_ui()
        app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error starting file transfer: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
