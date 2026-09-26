"""Loopback-only synthetic demo, not an OAuth server or security control."""
import asyncio
import json
import os
from auth_audit_jev import AuditPlugin


async def fake_jev(request):
    """A scripted fixture; no provider traffic, intelligence, or detection claim."""
    suspicious = request["state"]["outcome"] == "failure"
    choice = "suspicious" if suspicious else "routine"
    return {"model": "jev-latest", "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0},
            "answers": {"assessment": {"type": "choice", "choice": choice, "confidence": .95,
                                       "probabilities": {"suspicious": .95 if suspicious else .025,
                                                         "routine": .025 if suspicious else .95,
                                                         "other": .025}}}}


async def serve(host="0.0.0.0", port=8765):
    alerts = []
    plugin = AuditPlugin(transport=fake_jev, alert=alerts.append)
    await plugin.start()

    async def handle(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
            if len(request) > 4096:
                raise ValueError("request too large")
            method, path, _ = request.split(b"\r\n", 1)[0].split(b" ", 2)
            if method == b"GET" and path == b"/health":
                code, body, content_type = 200, json.dumps({"healthy": await plugin.health_check(), "mode": "synthetic-only"}), "application/json"
            elif method == b"GET" and path == b"/metrics":
                code, body, content_type = 200, plugin.metrics.prometheus(), "text/plain; version=0.0.4"
            elif method == b"GET" and path == b"/alerts":
                code, body, content_type = 200, json.dumps(alerts[-20:]), "application/json"
            elif method == b"POST" and path == b"/demo":
                # Fixed synthetic envelope only; never parse user-supplied event payloads.
                await plugin.emit({"event": {"event_type": "user_authentication_failed", "severity": "warning"}})
                await plugin.join()  # Demo-only: allows an immediately visible fixture result.
                code, body, content_type = 200, json.dumps({"scripted_alerts": alerts[-20:], "mode": "synthetic-only"}), "application/json"
            else:
                code, body, content_type = 404, '{"error":"not_found"}', "application/json"
            raw = body.encode("utf-8")
            writer.write((f"HTTP/1.1 {code} {'OK' if code == 200 else 'Not Found'}\r\n"
                          f"Content-Type: {content_type}\r\nContent-Length: {len(raw)}\r\n"
                          "Connection: close\r\n\r\n").encode("ascii") + raw)
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, TimeoutError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    try:
        server = await asyncio.start_server(handle, host, port)
        async with server:
            await server.serve_forever()
    finally:
        await plugin.close()


if __name__ == "__main__":
    asyncio.run(serve(port=int(os.environ.get("PORT", "8765"))))
