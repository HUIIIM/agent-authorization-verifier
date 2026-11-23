"""RFC 9421 derived components and signature base construction, restricted
to the component set used by the WIMSE HTTP signature profile
(draft-ietf-wimse-http-signature-09, section 3).

Supported derived components: @method, @path, @query, @authority, @status,
each optionally with the ;req parameter (value taken from the paired
request), plus ordinary header field components. Component parameters other
than ;req (for example ;sf, ;bs, ;name, ;key) are out of scope for v1 and
raise ComponentError, which the verifier reports at the BASE stage.
"""

from __future__ import annotations

from .httpmsg import HttpMessage
from .sf import SFInnerList, SFItem, SFString, serialize_item, serialize_member

DERIVED_COMPONENTS = {"@method", "@path", "@query", "@authority", "@status"}

_DEFAULT_PORTS = {443}  # https; the profile's exchanges are https (wimse-aud scheme)


class ComponentError(ValueError):
    """Raised when a component value cannot be derived from the message."""


def component_name(item: SFItem) -> str:
    if not isinstance(item.value, SFString):
        raise ComponentError("component identifier is not a string")
    return item.value.value


def is_req(item: SFItem) -> bool:
    return item.params.get("req") is True


def _authority_value(host_header: str) -> str:
    """RFC 9421 section 2.2.3: lowercase hostname; the port is omitted when
    it is the default port for the scheme, and can therefore differ from the
    CONNECT request target (draft-ietf-wimse-http-signature-09, section 3,
    change #419 relative to -08)."""
    host = host_header.strip()
    if host.startswith("["):  # IPv6 literal
        end = host.find("]")
        name = host[: end + 1].lower()
        rest = host[end + 1 :]
        port = rest[1:] if rest.startswith(":") else None
    elif ":" in host:
        name, port = host.rsplit(":", 1)
        name = name.lower()
    else:
        name, port = host.lower(), None
    if port is not None and port.isdigit() and int(port) in _DEFAULT_PORTS:
        port = None
    return f"{name}:{port}" if port else name


def derived_value(name: str, message: HttpMessage) -> str:
    if name == "@method":
        if message.kind != "request" or message.method is None:
            raise ComponentError("@method requires a request message")
        return message.method
    if name == "@status":
        if message.kind != "response" or message.status_code is None:
            raise ComponentError("@status requires a response message")
        return str(message.status_code)
    if name == "@path":
        if message.kind != "request":
            raise ComponentError("@path requires a request message")
        if message.method == "CONNECT":
            raise ComponentError("@path cannot be derived for a CONNECT request")
        path, _ = message.request_parts()
        return path if path else "/"
    if name == "@query":
        if message.kind != "request":
            raise ComponentError("@query requires a request message")
        if message.method == "CONNECT":
            raise ComponentError("@query cannot be derived for a CONNECT request")
        _, query = message.request_parts()
        return "?" + query if query is not None else "?"
    if name == "@authority":
        host = message.host
        if host is None:
            if message.kind == "request" and message.method == "CONNECT":
                host = message.target
            if host is None:
                raise ComponentError("@authority requires a Host header or CONNECT target")
        return _authority_value(host)
    raise ComponentError(f"unsupported derived component {name!r}")


def component_value(
    item: SFItem,
    message: HttpMessage,
    paired_request: HttpMessage | None,
    sender_mode: bool = False,
) -> str:
    """Resolve one covered component to its signature-base value.

    sender_mode is used only by the test-vector constructor to mimic a
    sender: a sender that (nonconformantly) signs @path for a CONNECT
    request puts "/" in the base, as documented in the suite's N-02 entry.
    The verifier never uses sender_mode: for verification, @path and
    @query are underivable for CONNECT and raise ComponentError."""
    name = component_name(item)
    extra = set(item.params) - {"req"}
    if extra:
        raise ComponentError(f"component parameter(s) {sorted(extra)} are not supported in v1")
    source = message
    if is_req(item):
        if paired_request is None:
            raise ComponentError(f"component {name!r};req requires the paired request")
        source = paired_request
    if name.startswith("@"):
        if name not in DERIVED_COMPONENTS:
            raise ComponentError(f"unsupported derived component {name!r}")
        if sender_mode and source.method == "CONNECT" and name in ("@path", "@query"):
            return "/" if name == "@path" else "?"
        return derived_value(name, source)
    value = source.header(name)
    if value is None:
        raise ComponentError(f"header field {name!r} not present in message")
    return value


def build_signature_base(
    message: HttpMessage,
    member: SFInnerList,
    paired_request: HttpMessage | None,
    sender_mode: bool = False,
) -> str:
    """Construct the RFC 9421 signature base for one Signature-Input member:
    one "component": value line per covered component, then the
    "@signature-params" line; LF line endings, no trailing newline."""
    lines: list[str] = []
    for item in member.items:
        value = component_value(item, message, paired_request, sender_mode=sender_mode)
        lines.append(f"{serialize_item(item)}: {value}")
    params_label = serialize_item(SFItem(value=SFString("@signature-params")))
    lines.append(f"{params_label}: {serialize_member(member)}")
    return "\n".join(lines)
