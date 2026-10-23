"""Application entry point for USB Sentinel.

Executes when the user runs:
    python -m usb_sentinel          # Launches interactive CLI
    python -m usb_sentinel --web    # Launches local web dashboard
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from usb_sentinel.cli import main as cli_main


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse entry arguments and route to CLI or Web dashboard."""
    raw_args = list(argv if argv is not None else sys.argv[1:])

    # If --web is requested, route to the web dashboard server
    if "--web" in raw_args:
        parser = argparse.ArgumentParser(
            description="USB Sentinel: Automated USB Mass Storage Threat Detection & Quarantine Watchdog",
        )
        parser.add_argument("--web", action="store_true", help="Launch the local web dashboard.")
        parser.add_argument("--port", type=int, default=5000, help="Web dashboard port (default: 5000).")
        parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode.")
        args = parser.parse_args(raw_args)

        from usb_sentinel.web_app import run_web

        run_web(port=args.port, debug=args.debug)
        return 0

    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
