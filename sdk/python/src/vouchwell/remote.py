"""Ship a local log's receipts to a Vouchwell hub.

The local log stays the source of truth; the hub is a replica that verifies
every receipt before storing it. ``push`` sends whatever the hub doesn't have
yet, in batches, and is safe to call repeatedly: the batch id is derived from
the batch's contents, so a retry the hub already accepted is a no-op.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from .log import ProofLog


class HubError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"hub answered {status} {code}: {message}")
        self.status = status
        self.code = code


def _loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_url(url: str, allow_insecure: bool) -> str:
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        return url.rstrip("/")
    if u.scheme == "http" and (_loopback(u.hostname or "") or allow_insecure):
        return url.rstrip("/")
    raise ValueError(
        f"{url} is plain HTTP: the API key would cross the network unencrypted. "
        "Use https://, or allow_insecure=True on a network you trust."
    )


def _request(method: str, url: str, token: str, body: Any = None, timeout: float = 15) -> tuple[int, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("authorization", f"Bearer {token}")
    req.add_header("accept", "application/json")
    if data is not None:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:  # noqa: S310  (URL checked above)
            return res.status, json.loads(res.read() or b"null")
    except urllib.error.HTTPError as err:
        try:
            payload = json.loads(err.read() or b"null")
        except ValueError:
            payload = None
        return err.code, payload


def _error(status: int, payload: Any) -> HubError:
    e = (payload or {}).get("error", {}) if isinstance(payload, dict) else {}
    return HubError(status, e.get("code", "error"), e.get("message", "unexpected response"))


def push(
    log: ProofLog,
    url: str,
    token: str,
    *,
    name: Optional[str] = None,
    batch_size: int = 200,
    allow_insecure: bool = False,
    timeout: float = 15,
) -> dict:
    """Send the hub every receipt it doesn't have. Returns ``{sent, hub_size}``.

    ``name`` is the log's name on the hub (defaults to its id). The hub binds
    that name to this log's key on first push and refuses a different key for
    it afterwards.
    """
    base = _check_url(url, allow_insecure)
    slug = name or log.log_id
    status, payload = _request(
        "POST",
        f"{base}/v1/logs",
        token,
        {"slug": slug, "canonical": log.log_id, "kid": log.identity.kid, "publicKey": log.identity.public_key},
        timeout,
    )
    if status != 200:
        raise _error(status, payload)

    status, head = _request("GET", f"{base}/v1/logs/{urllib.parse.quote(slug, safe='')}/head", token, None, timeout)
    if status != 200:
        raise _error(status, head)
    cursor = int(head["size"])
    if cursor > log.size:
        raise HubError(409, "hub_ahead", f"the hub holds {cursor} receipts for {slug}, more than this log's {log.size}")

    sent = 0
    while cursor < log.size:
        batch = log.entries[cursor : cursor + batch_size]
        digest = hashlib.sha256("".join(r["attest"]["sig"] for r in batch).encode()).hexdigest()[:16]
        status, res = _request(
            "POST",
            f"{base}/v1/logs/{urllib.parse.quote(slug, safe='')}/receipts",
            token,
            {"receipts": batch, "batchId": f"b_{slug}_{batch[0]['seq']}_{len(batch)}_{digest}"},
            timeout,
        )
        if status != 200:
            raise _error(status, res)
        sent += int(res["size"]) - cursor
        cursor = int(res["size"])
    return {"sent": sent, "hub_size": cursor}
