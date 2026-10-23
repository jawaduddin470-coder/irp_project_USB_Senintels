"""Vercel Serverless Function entry point for USB Sentinel Web Dashboard."""

from __future__ import annotations

from usb_sentinel.web_app import create_app

app = create_app()


class VercelPathMiddleware:
    """WSGI middleware ensuring Flask receives the original user request path on Vercel."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # Inspect Vercel edge headers and WSGI environment for original URL path
        candidate_path = (
            environ.get("HTTP_X_MATCHED_PATH")
            or environ.get("HTTP_X_FORWARDED_PATH")
            or environ.get("RAW_URI")
            or environ.get("REQUEST_URI")
        )
        if candidate_path:
            path_only = candidate_path.split("?")[0]
            if path_only and path_only != "/api/index":
                environ["PATH_INFO"] = path_only

        return self.wsgi_app(environ, start_response)


app.wsgi_app = VercelPathMiddleware(app.wsgi_app)

if __name__ == "__main__":
    app.run()
