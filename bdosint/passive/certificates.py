"""Live TLS certificate inspection (no bypass, no downgrade attempts)."""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("bdosint")


def collect(host: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Connect once with system trust store; read the served certificate."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                proto = tls.version() or "unknown"
    except ssl.SSLCertVerificationError as exc:
        return {"error": f"certificate verification failed: {exc.verify_message}"}
    except (socket.timeout, TimeoutError):
        return {"error": f"timeout connecting to {host}:{port}"}
    except (ConnectionRefusedError, OSError) as exc:
        return {"error": f"connection error: {exc}"}

    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    not_after_raw = cert.get("notAfter")
    status = "unknown"
    days_left: int | None = None
    if not_after_raw:
        try:
            expiry = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            status = "expired" if days_left < 0 else ("expiring soon" if days_left <= 30 else "valid")
        except ValueError:
            pass

    return {
        "host": host, "port": port,
        "subject": dict(x[0] for x in cert.get("subject", ())) if cert.get("subject") else {},
        "issuer": dict(x[0] for x in cert.get("issuer", ())) if cert.get("issuer") else {},
        "san": san,
        "not_before": cert.get("notBefore"),
        "not_after": not_after_raw,
        "days_remaining": days_left,
        "validity_status": status,
        "protocol": proto,
        "note": "Observed served certificate only. No downgrade or bypass attempted.",
    }
