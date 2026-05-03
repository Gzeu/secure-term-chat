#!/usr/bin/env python3
"""
Launch script for Audit and Compliance System
Easy entry point for comprehensive audit trail and compliance monitoring
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from audit_compliance_ui import create_audit_compliance_ui

def main():
    """Launch audit and compliance system"""
    print("📋 Starting Audit and Compliance System...")
    print("🔍 Comprehensive audit trail with real-time monitoring")
    print("⚖️ Multi-framework compliance reporting")
    print("📊 Automated violation detection and alerts")
    print("─" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        app = create_audit_compliance_ui()
        app.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error starting audit and compliance: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
