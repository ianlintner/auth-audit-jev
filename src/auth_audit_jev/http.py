"""Bounded HTTPS plumbing shared by the shadow workers.

One dedicated thread, one in-flight request, redirects and proxies disabled,
response size capped, duplicate JSON keys and non-finite numbers rejected. No
retries: an at-most-once observation is cheaper than an unbounded retry loop
against a decision service.
"""
from __future__ import annotations

import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler, HTTPRedirectHandler


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post_json(url, request_payload, api_key, timeout, max_bytes):
    """POST a JSON payload and return the parsed response, rejecting surprises."""
    payload = json.dumps(request_payload, separators=(",", ":")).encode("utf-8")
    req = Request(url, payload, headers={"Authorization": "Bearer " + api_key,
                                         "Content-Type": "application/json",
                                         "Accept-Encoding": "identity"}, method="POST")
    opener = build_opener(ProxyHandler({}), HTTPSHandler(), _NoRedirect())
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("oversized response")

    def reject_constant(_):
        raise ValueError("nonfinite response")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate response key")
            result[key] = value
        return result

    return json.loads(raw, parse_constant=reject_constant, object_pairs_hook=unique)


def bounded_transport(post, timeout, max_bytes, thread_name):
    """Wrap a blocking `post(request, timeout, max_bytes)` call for async use.

    A cancelled `wait_for` cannot kill a socket thread, so the semaphore refuses
    to hand more work to the executor than it can run; excess callers fail fast
    instead of filling ThreadPoolExecutor's unbounded internal queue.
    """
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=thread_name)
    slot = threading.BoundedSemaphore(1)

    def bounded(request):
        try:
            return post(request, timeout, max_bytes)
        finally:
            slot.release()

    async def transport(request):
        if not slot.acquire(blocking=False):
            raise RuntimeError("transport busy")
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(executor, bounded, request)
        except RuntimeError:
            slot.release()
            raise
        return await future

    def close():
        executor.shutdown(wait=False, cancel_futures=True)

    return transport, close
