"""Vercel Serverless Function entry point for USB Sentinel Web Dashboard."""

from __future__ import annotations

from usb_sentinel.web_app import create_app

# Vercel's Python runtime binds to the WSGI 'app' callable
app = create_app()

if __name__ == "__main__":
    app.run()
