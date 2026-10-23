"""Vercel Serverless Function entry point for USB Sentinel Web Dashboard."""

from __future__ import annotations

from flask import request
from usb_sentinel.web_app import create_app

app = create_app()


@app.route("/api/debug")
@app.route("/debug")
def debug_route():
    return {
        "PATH_INFO": request.environ.get("PATH_INFO"),
        "SCRIPT_NAME": request.environ.get("SCRIPT_NAME"),
        "REQUEST_URI": request.environ.get("REQUEST_URI"),
        "RAW_URI": request.environ.get("RAW_URI"),
        "HTTP_X_MATCHED_PATH": request.environ.get("HTTP_X_MATCHED_PATH"),
        "HTTP_X_FORWARDED_PATH": request.environ.get("HTTP_X_FORWARDED_PATH"),
        "headers": dict(request.headers),
    }


if __name__ == "__main__":
    app.run()
