#!/usr/bin/env python3
"""
Cleanup Expired Blocks Service
Automatically deactivates blocks that have passed their unblock_at time
"""

import sys
from pathlib import Path
import time
from datetime import datetime

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from blocking_engine import BlockingEngine


def cleanup_job():
    """Run cleanup and print results"""
    print(f"\n{'='*60}")
    print(f"🧹 Running block cleanup at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    try:
        count = BlockingEngine.cleanup_expired_blocks()

        if count > 0:
            print(f"✅ Cleaned up {count} expired block(s)")
        else:
            print(f"ℹ️  No expired blocks found")

    except Exception as e:
        print(f"❌ Error during cleanup: {e}")
        import traceback
        traceback.print_exc()


def run_once():
    """Run cleanup once and exit"""
    cleanup_job()


def run_daemon(interval_minutes=5):
    """Run cleanup service as daemon"""
    print(f"{'='*60}")
    print(f"🚀 SSH Guardian - Block Cleanup Service")
    print(f"{'='*60}")
    print(f"Interval: Every {interval_minutes} minutes")
    print(f"Press Ctrl+C to stop")
    print(f"{'='*60}\n")

    # Run immediately on start
    cleanup_job()

    # Keep running
    try:
        interval_seconds = interval_minutes * 60
        while True:
            time.sleep(interval_seconds)
            cleanup_job()
    except KeyboardInterrupt:
        print(f"\n\n{'='*60}")
        print(f"⏹️  Cleanup service stopped")
        print(f"{'='*60}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SSH Guardian Block Cleanup Service")
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run as daemon service (continuous)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Cleanup interval in minutes (default: 5)"
    )

    args = parser.parse_args()

    if args.daemon:
        run_daemon(args.interval)
    else:
        run_once()
