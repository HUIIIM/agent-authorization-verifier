"""RFC 9421 derived components and signature base construction, restricted
to the component set used by the WIMSE HTTP signature profile
(draft-ietf-wimse-http-signature-09, section 3).

Supported derived components: @method, @path, @query, @authority, @status,
each optionally with the ;req parameter (value taken from the paired
request), plus ordinary header field components. Component parameters other
than ;req (for example ;sf, ;bs, ;name, ;key) are out of scope for v1 and
raise ComponentError, which the verifier reports as a BASE-stage failure.

Signature base construction follows the RFC 9421 Section 2.5 algorithm for
this subset, including its three error rules that matter here:

* step 2.1 -- a component identifier (including its parameters) that occurs
  more than once in the covered components is an error (D-1);
* step 2.5, third bullet -- the ``req`` parameter on a component of a
  request is an error; on a response it selects the related request as the
  context, and nothing else does (D-2);
* step 4 -- a signature base containing any non-ASCII character is an error
  (D-4).

Every such error raises ComponentError. There is no fallback path: a value
is never taken from a message other than the one the identifier names.

Profile assumption (scheme and default ports, D-5): the message model
carries no scheme of its own. The scheme used for @authority default-port
omission is resolved by a two-level rule, and the rule is final:

1. an artifact that carries an explicit scheme wins -- in this message
   model that is an absolute-form request target (RFC 9112 Section 3.2.2,
   for example ``GET http://svc.example:80/x HTTP/1.1``), which is the
   artifact's own @scheme (RFC 9421 Section 2.2.4);
2. otherwise the scheme is the profile default, ``https``: WIMSE
   workload-to-workload exchanges are https, as the wimse-aud values of the
   profile show.

The default port is then looked up per scheme in DEFAULT_PORTS (https 443,
http 80). A scheme with no entry has no default port, so its port is never
omitted.
"""

from __future__ import annotations

from .httpmsg import HttpMessage
from .sf import SFInnerList, SFItem, SFString, serialize_item, serialize_member

DERIVED_COMPONENTS = {"@method", "@path", "@query", "@authority", "@status"}

PROFILE_DEFAULT_SCHEME = "https"
"""Profile assumption: an artifact with no explicit scheme is https."""

DEFAULT_PORTS: dict[str, int] = {"https": 443, "http": 80}
"""Default port per scheme (RFC 9110 Sections 4.2.1 and 4.2.2)."""

# Error codes carried by ComponentError; the verifier reports them as the
# BASE stage code.
E_BASE_COMPONENT = "E_BASE_COMPONENT"
E_BASE_DUPLICATE_COMPONENT = "E_BASE_DUPLICATE_COMPONENT"
E_BASE_REQ_MISUSE = "E_BASE_REQ_MISUSE"
E_BASE_NON_ASCII = "E_BASE_NON_ASCII"


class ComponentError(ValueError):
    """Raised when a component value cannot be derived from the message, or
    when the covered components violate an RFC 9421 Section 2.5 error rule.
    Always a hard error: the signature base is not produced."""

    def __init__(self, detail: str, code: str = E_BASE_COMPONENT) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def component_name(item: SFItem) -> str:
    if not isinstance(item.value, SFString):
        raise ComponentError("component identifier is not a string")
    return item.value.value


def is_req(item: SFItem) -> bool:
    return item.params.get("req") is True


def artifact_scheme(message: HttpMessage) -> str | None:
    """The explicit scheme an artifact carries, or None (level 1 of the
    two-level scheme rule). In this message model the only carrier is an
    absolute-form request target; schemes compare case-insensitively
    (RFC 9110 Section 4.2.3), so the value is lowercased."""
    if message.kind != "request" or not message.target:
        return None
    target = message.target
    if "://" not in target:
        return None
    scheme = target.split("://", 1)[0]
    if not scheme or not all(c.isalnum() or c in "+-." for c in scheme):
        return None
    return scheme.lower()


def resolve_scheme(message: HttpMessage) -> str:
    """Two-level, final: the artifact's explicit scheme wins; otherwise the
    profile default (https)."""
    return artifact_scheme(message) or PROFILE_DEFAULT_SCHEME


def _authority_value(host_header: str, scheme: str = PROFILE_DEFAULT_SCHEME) -> str:
    """RFC 9421 section 2.2.3: lowercase hostname; the port is omitted when
    it is the default port for the scheme, and can therefore differ from the
    CONNECT request target (draft-ietf-wimse-http-signature-09, section 3,
    change #419 relative to -08). The default port comes from DEFAULT_PORTS
    for the given scheme; the scheme defaults to the profile assumption
    (https) when the caller has no explicit one."""
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
    default_port = DEFAULT_PORTS.get(scheme.lower())
    if port is not None and port.isdigit() and int(port) == default_port:
        port = None
    return f"{name}:{port}" if port else name


def _target_authority(message: HttpMessage) -> str | None:
    """Authority of an absolute-form request target (RFC 9112 Section
    3.2.2: the target's authority takes precedence over Host)."""
    if artifact_scheme(message) is None:
        return None
    rest = (message.target or "").split("://", 1)[1]
    for sep in "/?#":
        rest = rest.split(sep, 1)[0]
    return rest or None


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
        if message.kind != "request":
            raise ComponentError("@authority requires a request message")
        host = _target_authority(message) or message.host
        if host is None:
            if message.method == "CONNECT":
                host = message.target
            if host is None:
                raise ComponentError("@authority requires a Host header or CONNECT target")
        return _authority_value(host, resolve_scheme(message))
    raise ComponentError(f"unsupported derived component {name!r}")


def _context_message(
    name: str,
    item: SFItem,
    message: HttpMessage,
    paired_request: HttpMessage | None,
) -> HttpMessage:
    """RFC 9421 Section 2.5 step 2.5: pick the message the component value
    comes from. Misuse of ;req is a hard error in every case (D-2); there is
    no fallback from one message to the other."""
    if "req" not in item.params:
        return message
    label = f"component {name!r};req"
    if item.params["req"] is not True:
        raise ComponentError(
            f"{label} must be the boolean flag ;req (true), got {item.params['req']!r}",
            E_BASE_REQ_MISUSE,
        )
    if message.kind != "response":
        raise ComponentError(
            f"{label} is used on a request; ;req is only defined for a response's "
            "signature (RFC 9421 Section 2.5)",
            E_BASE_REQ_MISUSE,
        )
    if paired_request is None:
        raise ComponentError(f"{label} requires the paired request", E_BASE_REQ_MISUSE)
    if paired_request.kind != "request":
        raise ComponentError(f"{label}: the paired message is not a request", E_BASE_REQ_MISUSE)
    return paired_request


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
    source = _context_message(name, item, message, paired_request)
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
    """Construct the RFC 9421 signature base (Section 2.5) for one
    Signature-Input member: one "component": value line per covered
    component, then the "@signature-params" line; LF line endings, no
    trailing newline. Raises ComponentError for a duplicated component
    identifier (step 2.1), any ;req misuse (step 2.5), any underivable
    component, and a non-ASCII result (step 4)."""
    lines: list[str] = []
    seen: set[str] = set()
    for item in member.items:
        identifier = serialize_item(item)
        if identifier in seen:
            raise ComponentError(
                f"component identifier {identifier} is covered more than once "
                "(RFC 9421 Section 2.5 step 2.1)",
                E_BASE_DUPLICATE_COMPONENT,
            )
        seen.add(identifier)
        value = component_value(item, message, paired_request, sender_mode=sender_mode)
        lines.append(f"{identifier}: {value}")
    params_label = serialize_item(SFItem(value=SFString("@signature-params")))
    lines.append(f"{params_label}: {serialize_member(member)}")
    base = "\n".join(lines)
    if not base.isascii():
        offenders = sorted({f"U+{ord(c):04X}" for c in base if not c.isascii()})
        raise ComponentError(
            f"signature base contains non-ASCII character(s) {', '.join(offenders)} "
            "(RFC 9421 Section 2.5 step 4)",
            E_BASE_NON_ASCII,
        )
    return base
