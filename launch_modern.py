#!/usr/bin/env python3
"""
Launch script for modern UI
Easy entry point for the enhanced terminal interface
"""

import sys
import asyncio
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from modern_ui import ModernChatApp

def main():
    """Launch the modern chat application"""
    print("🌟 Starting secure-term-chat with Modern UI...")
    print("🎨 Enhanced terminal interface with advanced features")
    print("🔒 End-to-end encryption and security features")
    print("─" * 50)
    
    try:
        app = ModernChatApp()
        app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
