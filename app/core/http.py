import logging
import traceback
from uuid import uuid4

from starlette.responses import JSONResponse


def error_body(code, message, request_id):
    return {"error": {"code": code, "message": message, "request_id": request_id}}


class RequestBoundary:
    def __init__(self, app, max_body_bytes):
        self.app = app
        self.maximum = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = str(uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        started = False

        async def secure_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message.setdefault("headers", []).extend(
                    [
                        (b"x-request-id", request_id.encode()),
                        (b"x-content-type-options", b"nosniff"),
                        (b"cache-control", b"no-store"),
                    ]
                )
            await send(message)

        async def too_large():
            response = JSONResponse(
                error_body("BODY_TOO_LARGE", "Cuerpo demasiado grande", request_id),
                status_code=413,
            )
            await response(scope, receive, secure_send)

        content_lengths = [
            value for name, value in scope.get("headers", []) if name.lower() == b"content-length"
        ]
        if (
            len(content_lengths) == 1
            and len(content_lengths[0]) <= 20
            and content_lengths[0].isdigit()
            and int(content_lengths[0]) > self.maximum
        ):
            return await too_large()

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(chunk) > self.maximum - len(body):
                return await too_large()
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def buffered_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        try:
            await self.app(scope, buffered_receive, secure_send)
        except Exception as exc:
            frames = [
                (f.filename, f.lineno, f.name) for f in traceback.extract_tb(exc.__traceback__)
            ]
            logging.getLogger("vulntrack").error(
                "unexpected_error request_id=%s type=%s frames=%s",
                request_id,
                type(exc).__name__,
                frames,
            )
            if not started:
                response = JSONResponse(
                    error_body("INTERNAL_ERROR", "Error interno", request_id), status_code=500
                )
                await response(scope, receive, secure_send)
            else:
                # Abort an incomplete response with a sanitized exception for the ASGI server.
                raise RuntimeError("Response interrupted; see sanitized application log") from None
