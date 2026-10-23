"""Minimal mitmproxy add-on: replace one game codepatch and its fileinfo row.

Scope: only codepatch/assembly-csharp-patch and its matching line in the
/abhotupdates/.../fileinfo response. Other traffic is not blocked or modified.
No licensing, keys, anti-detection, reporting changes, or upload to a remote server.
"""
from __future__ import annotations

import gzip
import logging
import re
from pathlib import Path
from urllib.parse import unquote

from mitmproxy import http

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / "payload"
ENTRY = b"codepatch/assembly-csharp-patch"
LINE = re.compile(rb"(?m)^codepatch/assembly-csharp-patch,[^\r\n]*", re.IGNORECASE)
# The CDN appends a base64 SHA-1 to the asset basename and encodes characters
# outside [A-Za-z0-9] as tilde + hex, e.g. '=' -> '~3D'. A hash such as
# "U6HNZ6HuhXpDCGzXQhn2VsL5rVs=" becomes "...u6hn...~3d" after
# route_path() normalisation. Permit those complete ~HH escapes, but keep
# matching anchored to exactly the codepatch/assembly-csharp-patch basename.
ASSET_ENDPOINT = re.compile(
    r"(?:^|/)codepatch/assembly-csharp-patch(?:[._-](?:[a-z0-9._-]|~[0-9a-f]{2}){1,95})?/?$",
    re.IGNORECASE,
)
LOGGER = logging.getLogger("assembly_proxy")


def route_path(path: str) -> str:
    return unquote(path.split("?", 1)[0]).rstrip("/").lower()


def is_fileinfo(path: str) -> bool:
    value = route_path(path)
    return "/abhotupdates/" in value and value.endswith("/fileinfo")


def is_assembly(path: str) -> bool:
    return bool(ASSET_ENDPOINT.search(route_path(path)))


def replace_row(content: bytes, new_line: bytes) -> tuple[bytes, int]:
    # Don't append or invent other asset entries: change exactly one existing row.
    if len(LINE.findall(content)) != 1:
        return content, 0
    return LINE.sub(lambda _: new_line, content, count=1), 1


def parse_range(header: str, size: int) -> tuple[int, int] | None:
    if not header.lower().startswith("bytes=") or "," in header:
        return None
    try:
        value = header[6:].strip()
        if "-" not in value:
            return None
        left, right = value.split("-", 1)
        if left and right:
            start, end = int(left), int(right)
        elif left:
            start, end = int(left), size - 1
        elif right:
            # RFC 7233 suffix range (last N bytes)
            n = int(right)
            if n < 1:
                return None
            start, end = max(0, size - n), size - 1
        else:
            return None
        if start < 0 or end < start or start >= size:
            return None
        return start, min(end, size - 1)
    except ValueError:
        return None


class AssemblyOnlyProxy:
    def __init__(self) -> None:
        self.asset = (PAYLOAD / "assembly-csharp-patch.gz").read_bytes()
        self.uncompressed = (PAYLOAD / "assembly-csharp-patch.bytes").read_bytes()
        self.line = (PAYLOAD / "fileinfo-line.txt").read_bytes().strip()
        if gzip.decompress(self.asset) != self.uncompressed:
            raise ValueError("Payload GZIP fails integrity check")
        fields = self.line.split(b",")
        if len(fields) != 8 or fields[0] != ENTRY or fields[3] != b"3":
            raise ValueError("fileinfo line does not match codepatch syntax")
        import base64
        import hashlib
        if fields[1] != base64.b64encode(hashlib.sha1(self.uncompressed).digest()) or \
           fields[4] != base64.b64encode(hashlib.sha1(self.asset).digest()) or \
           int(fields[2]) != len(self.uncompressed) or int(fields[5]) != len(self.asset):
            raise ValueError("Payload fileinfo SHA-1 or byte length mismatch; rebuild first")
        LOGGER.warning("Assembly-only proxy loaded: UnityFS %d bytes, GZIP %d bytes",
                       len(self.uncompressed), len(self.asset))

    def request(self, flow: http.HTTPFlow) -> None:
        path = flow.request.path
        normalized = route_path(path)
        # mitmdump abbreviates long URLs with an ellipsis. Log the full path
        # (never the query string) so an unexpected CDN suffix is diagnosable.
        if "/codepatch/" in normalized:
            LOGGER.warning(
                "codepatch request: matched=%s path=%s",
                is_assembly(path), normalized,
            )
        if is_fileinfo(path):
            # Avoid a cached 304 / partial fileinfo response, so the row can be patched.
            for h in ("If-None-Match", "If-Modified-Since", "Range", "If-Range"):
                flow.request.headers.pop(h, None)
            flow.request.headers["cache-control"] = "no-cache"
            return
        if not is_assembly(path):
            return
        method = flow.request.method.upper()
        if method not in ("GET", "HEAD"):
            return
        headers = {
            "Content-Type": "application/octet-stream",
            "Accept-Ranges": "bytes",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        }
        size = len(self.asset)
        requested_range = flow.request.headers.get("Range")
        if requested_range:
            match = parse_range(requested_range, size)
            if match is None:
                headers["Content-Range"] = f"bytes */{size}"
                flow.response = http.Response.make(416, b"", headers)
                return
            first, last = match
            chunk = self.asset[first:last + 1]
            headers["Content-Range"] = f"bytes {first}-{last}/{size}"
            flow.response = http.Response.make(206, b"" if method == "HEAD" else chunk, headers)
            flow.response.headers["Content-Length"] = str(len(chunk))
            LOGGER.warning("SERVED ASSEMBLY locally: gzip range %d-%d (HTTP 206)", first, last)
        else:
            flow.response = http.Response.make(200, b"" if method == "HEAD" else self.asset, headers)
            flow.response.headers["Content-Length"] = str(size)
            LOGGER.warning("SERVED ASSEMBLY locally: gzip %d bytes (HTTP 200)", size)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or not is_fileinfo(flow.request.path):
            return
        if flow.response.status_code != 200:
            LOGGER.warning("fileinfo passed through: upstream returned HTTP %d", flow.response.status_code)
            return
        try:
            body = flow.response.content
        except ValueError as exc:
            LOGGER.warning("fileinfo decoding failed, not modifying: %s", exc)
            return
        if body is None:
            return
        updated, n = replace_row(body, self.line)
        if n != 1:
            LOGGER.warning("fileinfo did not have exactly one codepatch line; left untouched")
            return
        flow.response.content = updated  # mitmproxy respects Content-Encoding / Content-Length
        for h in ("ETag", "Last-Modified", "Content-MD5", "Content-Range"):
            flow.response.headers.pop(h, None)
        flow.response.headers["cache-control"] = "no-store, no-cache, must-revalidate, max-age=0"
        LOGGER.info("fileinfo codepatch row replaced (other entries kept)")


addons = [AssemblyOnlyProxy()]
