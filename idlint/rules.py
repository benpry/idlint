"""Rule dataclass, built-in rules and their validators.

A rule is a compiled regex plus an optional validator. The validator receives
the match and the line it was found on and returns True to keep the match.
Validators only inspect the matched text and its neighbours, so they keep
working when a pattern is overridden in config.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote

Validator = Callable[[re.Match, str], bool]


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern | None = None  # None for file and header rules
    validator: Validator | None = None
    default_on: bool = True
    severity: str = "error"
    require_on_line: tuple[str, ...] = ()  # lowercase keywords, any one must appear

    def find(self, line: str) -> list[re.Match]:
        """Matches on one line that pass the keyword gate and the validator."""
        matches = list(self.pattern.finditer(line))
        if not matches:
            return matches
        if self.require_on_line:
            lowered = line.lower()
            if not any(word in lowered for word in self.require_on_line):
                return []
        if self.validator is not None:
            matches = [m for m in matches if self.validator(m, line)]
        return matches

    @staticmethod
    def span(m: re.Match) -> tuple[int, int]:
        """Span of the reported value: the `value` group if the pattern has one."""
        return m.span("value") if "value" in m.re.groupindex else m.span()

    @classmethod
    def value(cls, m: re.Match) -> str:
        start, end = cls.span(m)
        return m.string[start:end]


# --- validators -----------------------------------------------------------

_HEX = frozenset("0123456789abcdefABCDEF")


def _char(line: str, index: int) -> str:
    return line[index] if 0 <= index < len(line) else ""


def _prolific_id(m: re.Match, line: str) -> bool:
    if len(set(m.group(0).lower())) == 1:
        return False
    return _char(line, m.start() - 1) not in _HEX and _char(line, m.end()) not in _HEX


def _url_param(m: re.Match, line: str) -> bool:
    # A real ID starts with a letter or digit; placeholders such as {{%PROLIFIC_PID%}},
    # ${e://Field/PROLIFIC_PID} and their URL-encoded forms do not.
    return unquote(m.group(0).partition("=")[2])[:1].isalnum()


def _mturk(m: re.Match, line: str) -> bool:
    rest = m.group(0)[1:]
    return any(c.isdigit() for c in rest) and any(c.isalpha() for c in rest)


# Text just before a dotted quad that marks it as a version number: `version = "`,
# `==`, `>=`, a `v` prefix, or a product token as in the user agent `Chrome/120.0.0.0`.
_VERSION_BEFORE = re.compile(r"(?:version\W{0,6}|[=<>~!]=\s*|(?<![0-9A-Za-z])v|[A-Za-z]/)$", re.I)


def _ipv4(m: re.Match, line: str) -> bool:
    try:
        a, b, c, d = (int(part) for part in m.group(0).split("."))
    except ValueError:
        return False
    if max(a, b, c, d) > 255:
        return False
    if a in (0, 10, 127) or a >= 224:  # this-network, private, loopback, multicast/reserved/broadcast
        return False
    if (a, b) in ((169, 254), (192, 168)) or (a == 172 and 16 <= b <= 31):
        return False
    if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)):  # documentation
        return False
    return not _VERSION_BEFORE.search(line, max(0, m.start() - 32), m.start())


_UNIQUE_LOCAL = ipaddress.ip_network("fc00::/7")


def _ipv6(m: re.Match, line: str) -> bool:
    text = m.group(0)
    if "::" not in text and text.count(":") != 7:  # cheap reject for times, MACs
        return False
    try:
        ip = ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip in _UNIQUE_LOCAL)


_NUMBER = re.compile(r"-?\d+\.\d+")


def _lat_long(m: re.Match, line: str) -> bool:
    numbers = _NUMBER.findall(m.group(0))
    if len(numbers) != 2:
        return False
    a, b = abs(float(numbers[0])), abs(float(numbers[1]))
    return (a <= 90 and b <= 180) or (b <= 90 and a <= 180)


_PLACEHOLDER_DOMAINS = ("example.com", "example.org", "test.com")


def _email(m: re.Match, line: str) -> bool:
    local, _, domain = m.group(0).lower().rpartition("@")
    return local not in ("noreply", "git") and domain not in _PLACEHOLDER_DOMAINS


def _not_inside_number(m: re.Match, line: str) -> bool:
    return not (_char(line, m.start() - 1).isdigit() or _char(line, m.end()).isdigit())


def _ssn(m: re.Match, line: str) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area[0] == "9":
        return False
    return group != "00" and serial != "0000"


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _credit_card(m: re.Match, line: str) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    # Card networks issue numbers starting 2-6; this also drops 13-digit timestamps.
    return 13 <= len(digits) <= 19 and digits[0] in "23456" and _luhn(digits)


def _mac(m: re.Match, line: str) -> bool:
    digits = set(re.sub(r"[^0-9a-f]", "", m.group(0).lower()))
    return digits not in ({"0"}, {"f"})


_MONTHS = {name: i for i, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


def _valid_date(year: int, month: int, day: int) -> bool:
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    return True


def _date(m: re.Match, line: str) -> bool:
    text = m.group(0)
    word = re.search(r"[A-Za-z]{3}", text)
    numbers = [int(n) for n in re.findall(r"\d+", text)]
    if word:
        month = _MONTHS.get(word.group(0).lower())
        if month is None or len(numbers) != 2:
            return False
        day, year = numbers
        return _valid_date(year, month, day)
    if len(numbers) != 3:
        return False
    a, b, c = numbers
    if a > 31:  # year first
        return _valid_date(a, b, c)
    year = c if c > 99 else 2000 + c
    return _valid_date(year, a, b) or _valid_date(year, b, a)  # month/day or day/month


# --- patterns -------------------------------------------------------------

_B = r"(?<![0-9A-Za-z])"  # not preceded by a letter or digit
_E = r"(?![0-9A-Za-z])"  # not followed by a letter or digit
_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?"


def _rule(id: str, description: str, pattern: str | None = None, validator: Validator | None = None,
          flags: int = 0, **kwargs) -> Rule:
    compiled = re.compile(pattern, flags) if pattern is not None else None
    return Rule(id, description, compiled, validator, **kwargs)


_RULES = [
    _rule("prolific-id", "Prolific participant ID (24 hex characters)",
          _B + r"[0-9a-fA-F]{24}" + _E, _prolific_id),
    _rule("prolific-url-param", "PROLIFIC_PID, STUDY_ID or SESSION_ID URL parameter with a value",
          r"\b(?:PROLIFIC_PID|STUDY_ID|SESSION_ID)=(?P<value>[^&\s#\"']+)", _url_param),
    _rule("mturk-worker-id", "MTurk worker ID (A plus 11 to 13 uppercase letters or digits)",
          _B + r"A[A-Z0-9]{11,13}" + _E, _mturk),
    _rule("ipv4", "Public IPv4 address",
          r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])(?!\.\d)", _ipv4),
    _rule("ipv6", "Public IPv6 address",
          r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:.])", _ipv6),
    _rule("lat-long-pair", "Latitude/longitude pair with 4+ decimal places",
          r"(?<![0-9A-Za-z.])-?\d{1,3}\.\d{4,}[\"']?(?:[ \t]*,[ \t]*|[ \t]+)[\"']?-?\d{1,3}\.\d{4,}(?![0-9.])",
          _lat_long),
    _rule("email", "Email address",
          r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9-])",
          _email),
    _rule("phone", "Phone number (E.164 or North American with separators)",
          r"(?<![0-9A-Za-z+.-])(?:\+[1-9]\d{7,14}"
          r"|(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\) ?|[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4})(?![0-9])",
          _not_inside_number),
    _rule("us-ssn", "US Social Security number",
          r"(?<![0-9A-Za-z-])\d{3}-\d{2}-\d{4}(?![0-9A-Za-z-])", _ssn),
    _rule("credit-card", "Payment card number (13 to 19 digits, Luhn-valid)",
          r"(?<![0-9A-Za-z-])(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{5})(?![0-9A-Za-z-])",
          _credit_card),
    _rule("mac-address", "MAC address",
          r"(?<![0-9A-Za-z:-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Za-z:-])", _mac),
    _rule("date-of-birth", "Date on a line mentioning dob, birth or born",
          _B + r"(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"
          rf"|{_MONTH} \d{{1,2}},? \d{{4}}|\d{{1,2}} {_MONTH},? \d{{4}})(?!\d)",
          _date, flags=re.I, require_on_line=("dob", "birth", "born")),
    _rule("us-zip", "US ZIP code on a line mentioning zip or postal",
          r"(?<![0-9A-Za-z.-])\d{5}(?:-\d{4})?(?![0-9A-Za-z-])(?!\.\d)",
          default_on=False, require_on_line=("zip", "postal")),
    _rule("uuid", "Canonical UUID",
          r"(?<![0-9A-Za-z-])[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}(?![0-9A-Za-z-])",
          default_on=False),
    _rule("sensitive-column", "CSV/TSV/PSV header or JSON key with an identifying name"),
    _rule("unscannable-data-file", "Binary data file that cannot be scanned", severity="warning"),
    _rule("oversize-file", "Text file larger than the size limit, not scanned", severity="warning"),
]

BUILTIN_RULES: dict[str, Rule] = {rule.id: rule for rule in _RULES}
