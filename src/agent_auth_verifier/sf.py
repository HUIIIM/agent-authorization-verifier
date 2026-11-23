"""RFC 8941 Structured Field Values: the subset needed for HTTP message
signatures (RFC 9421) -- dictionaries, inner lists, items and parameters.

Only the constructs that appear in Signature / Signature-Input header fields
(and in the WIMSE profile built on them) are implemented: strings, tokens,
integers, decimals, booleans, byte sequences, inner lists and parameters.
Display strings and dates are intentionally out of scope for v1.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field


class SFParseError(ValueError):
    """Raised when a structured field value cannot be parsed."""


@dataclass(frozen=True)
class SFString:
    value: str


@dataclass(frozen=True)
class SFToken:
    value: str


@dataclass(frozen=True)
class SFBytes:
    value: bytes


SFValue = str | int | bool | SFString | SFToken | SFBytes
"""Bare SF values: str is a decimal kept in its literal form, int an integer,
bool a boolean, SFString a quoted string, SFToken a token, SFBytes a byte
sequence."""


@dataclass
class SFItem:
    value: SFValue
    params: dict[str, SFValue | bool] = field(default_factory=dict)
    """A bare item plus parameters; a parameter value of True means the
    parameter appeared without an explicit value (for example ;req)."""


@dataclass
class SFInnerList:
    items: list[SFItem] = field(default_factory=list)
    params: dict[str, SFValue | bool] = field(default_factory=dict)


SFMember = SFItem | SFInnerList


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def error(self, what: str) -> SFParseError:
        return SFParseError(f"{what} at offset {self.pos} in {self.text!r}")

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t"):
            self.pos += 1

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.pos += 1

    def parse_key(self) -> str:
        start = self.pos
        ch = self.peek()
        if not (ch.isalpha() and ch.islower() or ch == "*"):
            raise self.error("expected key")
        self.pos += 1
        while True:
            ch = self.peek()
            if ch and (ch.islower() or ch.isdigit() or ch in "_-.*%"):
                self.pos += 1
            else:
                break
        return self.text[start : self.pos]

    def parse_string(self) -> SFString:
        # self.text[self.pos] == '"'
        self.pos += 1
        out: list[str] = []
        while True:
            ch = self.peek()
            if ch == "":
                raise self.error("unterminated string")
            if ch == "\\":
                self.pos += 1
                esc = self.peek()
                if esc not in ('"', "\\"):
                    raise self.error("invalid string escape")
                out.append(esc)
                self.pos += 1
            elif ch == '"':
                self.pos += 1
                return SFString("".join(out))
            else:
                out.append(ch)
                self.pos += 1

    def parse_token(self) -> SFToken:
        start = self.pos
        ch = self.peek()
        if not (ch.isalpha() or ch == "*"):
            raise self.error("expected token")
        self.pos += 1
        while True:
            ch = self.peek()
            if ch and (ch.isalnum() or ch in "!#$%&'*+-.^_`|~:/"):
                self.pos += 1
            else:
                break
        return SFToken(self.text[start : self.pos])

    def parse_bytesequence(self) -> SFBytes:
        # self.text[self.pos] == ':'
        end = self.text.find(":", self.pos + 1)
        if end < 0:
            raise self.error("unterminated byte sequence")
        raw = self.text[self.pos + 1 : end]
        try:
            value = base64.b64decode(raw, validate=True)
        except binascii.Error as exc:
            raise self.error(f"invalid base64 in byte sequence: {exc}") from exc
        self.pos = end + 1
        return SFBytes(value)

    def parse_number(self) -> int | str:
        start = self.pos
        if self.peek() == "-":
            self.pos += 1
        digits = 0
        while self.peek().isdigit():
            self.pos += 1
            digits += 1
        if digits == 0:
            raise self.error("expected number")
        if self.peek() == ".":
            self.pos += 1
            frac = 0
            while self.peek().isdigit():
                self.pos += 1
                frac += 1
            if frac == 0 or frac > 3:
                raise self.error("invalid decimal")
            return self.text[start : self.pos]
        return int(self.text[start : self.pos])

    def parse_bare_item(self) -> SFValue:
        ch = self.peek()
        if ch == '"':
            return self.parse_string()
        if ch == ":":
            return self.parse_bytesequence()
        if ch == "?":
            self.pos += 1
            digit = self.peek()
            if digit not in ("0", "1"):
                raise self.error("invalid boolean")
            self.pos += 1
            return digit == "1"
        if ch == "-" or ch.isdigit():
            return self.parse_number()
        if ch.isalpha() or ch == "*":
            return self.parse_token()
        raise self.error("expected bare item")

    def parse_params(self) -> dict[str, SFValue | bool]:
        params: dict[str, SFValue | bool] = {}
        while self.peek() == ";":
            self.pos += 1
            self.skip_sp()
            name = self.parse_key()
            if self.peek() == "=":
                self.pos += 1
                params[name] = self.parse_bare_item()
            else:
                params[name] = True
        return params

    def parse_item(self) -> SFItem:
        value = self.parse_bare_item()
        params = self.parse_params()
        return SFItem(value=value, params=params)

    def parse_inner_list(self) -> SFInnerList:
        # self.text[self.pos] == '('
        self.pos += 1
        items: list[SFItem] = []
        while True:
            self.skip_sp()
            if self.peek() == ")":
                self.pos += 1
                break
            if self.peek() == "":
                raise self.error("unterminated inner list")
            items.append(self.parse_item())
            ch = self.peek()
            if ch not in (" ", ")"):
                raise self.error("expected space or ')' in inner list")
        params = self.parse_params()
        return SFInnerList(items=items, params=params)

    def parse_member(self) -> SFMember:
        if self.peek() == "(":
            return self.parse_inner_list()
        return self.parse_item()


def parse_dictionary(text: str) -> dict[str, SFMember]:
    """Parse an RFC 8941 dictionary (the shape of Signature-Input and
    Signature header field values). Member order is preserved."""
    parser = _Parser(text)
    members: dict[str, SFMember] = {}
    parser.skip_ows()
    if parser.peek() == "":
        return members
    while True:
        key = parser.parse_key()
        if parser.peek() == "=":
            parser.pos += 1
            member = parser.parse_member()
        else:
            member = SFItem(value=True, params=parser.parse_params())
        if key in members:
            raise SFParseError(f"duplicate dictionary key {key!r}")
        members[key] = member
        parser.skip_ows()
        if parser.peek() == "":
            return members
        if parser.peek() != ",":
            raise parser.error("expected ',' between dictionary members")
        parser.pos += 1
        parser.skip_ows()
        if parser.peek() == "":
            raise SFParseError("trailing comma in dictionary")


def serialize_bare(value: SFValue) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, SFString):
        escaped = value.value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, SFToken):
        return value.value
    if isinstance(value, SFBytes):
        return ":" + base64.b64encode(value.value).decode("ascii") + ":"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):  # decimal literal kept verbatim
        return value
    raise TypeError(f"cannot serialize {type(value).__name__}")


def serialize_params(params: dict[str, SFValue | bool]) -> str:
    out: list[str] = []
    for name, value in params.items():
        if value is True:
            out.append(f";{name}")
        else:
            out.append(f";{name}={serialize_bare(value)}")
    return "".join(out)


def serialize_item(item: SFItem) -> str:
    return serialize_bare(item.value) + serialize_params(item.params)


def serialize_member(member: SFMember) -> str:
    if isinstance(member, SFInnerList):
        inner = " ".join(serialize_item(item) for item in member.items)
        return f"({inner})" + serialize_params(member.params)
    return serialize_item(member)


def serialize_dictionary(members: dict[str, SFMember]) -> str:
    return ", ".join(f"{key}={serialize_member(member)}" for key, member in members.items())
