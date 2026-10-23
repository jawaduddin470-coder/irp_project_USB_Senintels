#!/usr/bin/env python3
"""Launcher script for USB Sentinel Web Dashboard.

Usage:
    python run_web.py
    python run_web.py --port 8080 --debug
"""

from __future__ import annotations

import argparse
import sys

from usb_sentinel.web_app import run_web


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Launch USB Sentinel Web Dashboard (127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to bind the web dashboard (default: 5000)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run Flask in debug mode",
    )
    args = parser.parse_args()

    try:
        run_web(host="127.0.0.1", port=args.port, debug=args.debug)
        return 0
    except KeyboardInterrupt:
        print("\n[*] Shutting down USB Sentinel Web Dashboard.")
        return 0
    except Exception as exc:
        print(f"[!] Server error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
