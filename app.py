"""Root application entrypoint for Vercel zero-config and WSGI runners."""

from __future__ import annotations

from usb_sentinel.web_app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
