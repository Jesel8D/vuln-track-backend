"""Explicit browser transport policy for the existing Bearer-only API."""

from uuid import uuid4

from starlette.datastructures import Headers
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from app.core.http import error_body

CORS_METHODS = ["GET", "POST"]
CORS_HEADERS = ["Accept", "Content-Type", "Authorization", "Idempotency-Key"]
CORS_EXPOSE_HEADERS = ["Location", "X-Request-ID", "Retry-After", "WWW-Authenticate"]


class BrowserCORSMiddleware(CORSMiddleware):
    def __init__(self, app, allow_origins, max_age):
        super().__init__(
            app,
            allow_origins=allow_origins,
            allow_credentials=False,
            allow_methods=CORS_METHODS,
            allow_headers=CORS_HEADERS,
            expose_headers=CORS_EXPOSE_HEADERS,
            max_age=max_age,
        )

    def preflight_response(self, request_headers: Headers):
        result = super().preflight_response(request_headers)
        request_id = str(uuid4())
        headers = {
            key: value
            for key, value in result.headers.items()
            if key not in {"content-type", "content-length"}
        }
        headers.update(
            {
                "X-Request-ID": request_id,
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            }
        )
        body = (
            {"status": "ok"}
            if result.status_code == 200
            else error_body(
                "CORS_PREFLIGHT_DENIED", "Origen, método o cabeceras no permitidos", request_id
            )
        )
        return JSONResponse(body, status_code=result.status_code, headers=headers)
