"""Minimal HTTP/1.1 message parsing for signature verification.

Parses the exact wire form used by the vector set (CRLF line endings): a
request or status start line, header fields, and an optional body. Header
field values are exposed the way RFC 9421 consumes them: leading and
trailing optional whitespace stripped, repeated fields combined with ", ".
"""

from __future__ import annotations

from dataclasses import dataclass, field


class MessageParseError(ValueError):
    """Raised when a message cannot be parsed into start line/headers/body."""


@dataclass
class HttpMessage:
    kind: str  # "request" or "response"
    method: str | None = None
    target: str | None = None
    status_code: int | None = None
    reason: str = ""
    version: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    """Header fields as (lowercased name, stripped value) in wire order."""
    body: bytes = b""

    def header_values(self, name: str) -> list[str]:
        lname = name.lower()
        return [value for (hname, value) in self.headers if hname == lname]

    def header(self, name: str) -> str | None:
        """Combined field value per RFC 9421 section 2.1, or None if absent."""
        values = self.header_values(name)
        if not values:
            return None
        return ", ".join(values)

    def has_header(self, name: str) -> bool:
        return bool(self.header_values(name))

    def set_header(self, name: str, value: str) -> None:
        lname = name.lower()
        self.headers = [(n, v) for (n, v) in self.headers if n != lname]
        self.headers.append((lname, value))

    def remove_header(self, name: str) -> None:
        lname = name.lower()
        self.headers = [(n, v) for (n, v) in self.headers if n != lname]

    @property
    def host(self) -> str | None:
        return self.header("host")

    def request_parts(self) -> tuple[str, str | None]:
        """Split a request target into (path, query-or-None)."""
        target = self.target or ""
        if "?" in target:
            path, query = target.split("?", 1)
            return path, query
        return target, None

    def serialize(self) -> str:
        if self.kind == "request":
            start = f"{self.method} {self.target} {self.version}"
        else:
            reason = f" {self.reason}" if self.reason else ""
            start = f"{self.version} {self.status_code}{reason}"
        lines = [start]
        for name, value in self.headers:
            lines.append(f"{_display_name(name)}: {value}")
        head = "\r\n".join(lines) + "\r\n\r\n"
        return head + self.body.decode("utf-8", errors="surrogateescape")


_DISPLAY_NAMES = {
    "host": "Host",
    "content-type": "Content-Type",
    "content-digest": "Content-Digest",
    "workload-identity-token": "Workload-Identity-Token",
    "signature": "Signature",
    "signature-input": "Signature-Input",
    "authorization": "Authorization",
    "txn-token": "Txn-Token",
}


def _display_name(name: str) -> str:
    return _DISPLAY_NAMES.get(name, name)


def parse_message(raw: str) -> HttpMessage:
    if "\r\n\r\n" in raw:
        head, body_text = raw.split("\r\n\r\n", 1)
    elif "\r\n" in raw:
        head, body_text = raw, ""
    else:
        raise MessageParseError("message has no CRLF header terminator")
    lines = head.split("\r\n")
    start_line = lines[0]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise MessageParseError(f"malformed header line: {line!r}")
        name, value = line.split(":", 1)
        headers.append((name.strip().lower(), value.strip(" \t")))
    body = body_text.encode("utf-8", errors="surrogateescape")
    if start_line.startswith("HTTP/"):
        parts = start_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise MessageParseError(f"malformed status line: {start_line!r}")
        return HttpMessage(
            kind="response",
            status_code=int(parts[1]),
            reason=parts[2] if len(parts) > 2 else "",
            version=parts[0],
            headers=headers,
            body=body,
        )
    parts = start_line.split(" ")
    if len(parts) != 3:
        raise MessageParseError(f"malformed request line: {start_line!r}")
    method, target, version = parts
    return HttpMessage(
        kind="request",
        method=method,
        target=target,
        version=version,
        headers=headers,
        body=body,
    )
