import ipaddress
from urllib.parse import urlparse


def _is_safe_url(url: str) -> bool:
    """Return False if the URL targets an internal/private resource (SSRF protection)."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        if not host or host.lower() == "localhost":
            return False
        try:
            ip = ipaddress.ip_address(host)
            return not (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved)
        except ValueError:
            return True  # Hostname — allowed
    except Exception:
        return False
