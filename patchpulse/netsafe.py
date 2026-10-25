"""Safe outbound HTTP for scanning customer websites.

Design goals:
  * Never let a user-entered address reach private/internal networks
    (SSRF protection) unless explicitly allowed (intranet / testing mode).
  * Pin the resolved IP for the whole request so DNS rebinding can't
    swap in an internal address between the check and the connection.
  * Hard limits on time, redirects and body size so a hostile site can't
    hang or flood the scanner.
  * Standard library only, so the app packages into one file.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import USER_AGENT

MAX_BODY = 512 * 1024
DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 5


class UnsafeTarget(Exception):
    """Raised when an address is not allowed to be scanned."""


class FetchError(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: dict  # lower-cased keys, last value wins; multi kept in raw_headers
    raw_headers: list
    body: bytes
    elapsed: float
    tls_version: str | None = None
    redirects: list = field(default_factory=list)

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def normalize_site_url(raw: str) -> str:
    """Turn what a beginner types ('mysite.com', 'www.mysite.com/', 'http://...')
    into a clean https://host[:port] base URL. Raises ValueError if hopeless."""
    s = (raw or "").strip()
    if not s:
        raise ValueError("Please type your website address, for example: mysite.com")
    if "://" not in s:
        s = "https://" + s
    parts = urlsplit(s)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Website address must start with http:// or https://")
    host = (parts.hostname or "").strip(".").lower()
    if not host or " " in host:
        raise ValueError("That doesn't look like a website address. Try something like mysite.com")
    if "." not in host and host != "localhost":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("That doesn't look like a full website address. Did you mean " + host + ".com?")
    try:
        host.encode("idna")
    except UnicodeError:
        raise ValueError("That website address has characters we can't read.")
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    if ":" in host and not host.startswith("["):  # bare IPv6
        netloc = f"[{host}]" + (f":{parts.port}" if parts.port and parts.port not in (80, 443) else "")
    return urlunsplit(("https" if parts.scheme == "https" else "http", netloc, "", "", ""))


def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"))
    )


def resolve_safe(host: str, port: int, allow_private: bool) -> str:
    """Resolve host and return one IP that is allowed to be contacted."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise FetchError(f"Couldn't find the website '{host}'. Check the spelling, or the domain may have expired.")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip not in ips:
            ips.append(ip)
    if not allow_private:
        bad = [str(i) for i in ips if not _ip_is_public(i)]
        if bad:
            raise UnsafeTarget(
                f"'{host}' points to a private/internal address ({', '.join(bad)}). "
                "For safety PatchPulse only checks public websites. "
                "(An admin can enable 'Allow private network addresses' in Settings.)"
            )
    # Prefer IPv4 for widest compatibility
    ips.sort(key=lambda i: i.version)
    return str(ips[0])


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, context, timeout):
        super().__init__(host, port=port, context=context, timeout=timeout)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


def make_ssl_context(verify: bool = True) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        try:  # bundled certifi when available (PyInstaller builds)
            import certifi  # type: ignore
            ctx.load_verify_locations(certifi.where())
        except Exception:
            pass
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url: str, *, method: str = "GET", headers: dict | None = None,
          allow_private: bool = False, verify_tls: bool = True,
          timeout: float = DEFAULT_TIMEOUT, follow_redirects: bool = True,
          max_body: int = MAX_BODY) -> Response:
    """Fetch a URL safely. Every redirect hop is re-validated."""
    start = time.monotonic()
    redirects: list[str] = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https"):
            raise FetchError(f"Refusing to follow a link to '{parts.scheme}:' address")
        host = parts.hostname
        if not host:
            raise FetchError("Bad address")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ip = resolve_safe(host, port, allow_private)
        remaining = max(1.0, timeout - (time.monotonic() - start))
        if parts.scheme == "https":
            conn = _PinnedHTTPSConnection(host, port, ip, make_ssl_context(verify_tls), remaining)
        else:
            conn = _PinnedHTTPConnection(host, port, ip, remaining)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity",
                "Connection": "close"}
        if headers:
            hdrs.update(headers)
        try:
            conn.request(method, path, headers=hdrs)
            resp = conn.getresponse()
            body = b""
            if method != "HEAD":
                body = resp.read(max_body + 1)[:max_body]
            tls_version = None
            if parts.scheme == "https" and conn.sock is not None:
                try:
                    tls_version = conn.sock.version()
                except Exception:
                    pass
            raw = resp.getheaders()
        except ssl.SSLCertVerificationError:
            raise
        except (socket.timeout, TimeoutError):
            raise FetchError("The website took too long to answer.")
        except ConnectionRefusedError:
            raise FetchError("The website refused the connection.")
        except (OSError, http.client.HTTPException) as e:
            raise FetchError(f"Couldn't connect to the website ({e.__class__.__name__}).")
        finally:
            conn.close()
        hmap = {k.lower(): v for k, v in raw}
        if follow_redirects and resp.status in (301, 302, 303, 307, 308) and "location" in hmap:
            nxt = urljoin(current, hmap["location"])
            redirects.append(nxt)
            current = nxt
            continue
        return Response(current, resp.status, hmap, raw, body,
                        time.monotonic() - start, tls_version, redirects)
    raise FetchError("The website redirected too many times.")


def get_certificate(host: str, port: int = 443, allow_private: bool = False,
                    timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Return {'ok': bool, 'not_after': epoch|None, 'issuer': str, 'error': str|None}."""
    ip = resolve_safe(host, port, allow_private)
    result = {"ok": False, "not_after": None, "issuer": "", "error": None, "tls_version": None}
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            with make_ssl_context(True).wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                result["tls_version"] = ss.version()
        result["ok"] = True
    except ssl.SSLCertVerificationError as e:
        result["error"] = getattr(e, "verify_message", None) or str(e)
        # Still read expiry with verification off so we can say *why*
        try:
            with socket.create_connection((ip, port), timeout) as sock:
                with make_ssl_context(False).wrap_socket(sock, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
                    result["tls_version"] = ss.version()
            cert = _decode_der(der)
        except Exception:
            return result
    except (OSError, ssl.SSLError) as e:
        result["error"] = f"secure connection failed ({e.__class__.__name__})"
        return result
    if cert and cert.get("notAfter"):
        try:
            result["not_after"] = ssl.cert_time_to_seconds(cert["notAfter"])
        except Exception:
            pass
        issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
        result["issuer"] = issuer.get("organizationName") or issuer.get("commonName", "")
    return result


def _decode_der(der: bytes) -> dict:
    """Best-effort decode of a DER cert without third-party libs."""
    import os
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)  # stdlib helper, stable since 3.x
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
