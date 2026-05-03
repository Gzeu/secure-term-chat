#!/usr/bin/env python3
"""
Launch script for Performance Dashboard
Easy entry point for real-time system monitoring
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from performance_dashboard import create_performance_dashboard

def main():
    """Launch the performance dashboard"""
    print("📊 Starting Performance Dashboard...")
    print("🔍 Real-time system monitoring and analysis")
    print("📈 Performance metrics and alerting")
    print("─" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        app = create_performance_dashboard()
        app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error starting dashboard: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
