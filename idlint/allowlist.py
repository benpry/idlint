"""The line allowlist: the `[allow_lines]` table of `.idlint.toml`.

Entries pin a suppression to a path, a rule and a hash of the line's content:

    [allow_lines]
    "data/pilot.csv:lat-long-pair:9f2c41d07a3e:17" = "campus building coords, public"

Only hashes are stored, never line text. `append` and `prune` edit the table's lines in
place and leave the rest of the config file, including its comments, untouched.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

TABLE = "allow_lines"
TABLE_COMMENT = (
    "# Lines judged not to be PII. `idlint allow` adds entries and `idlint prune` removes stale ones.\n"
    '# "path:rule:line-hash:line-number-hint" = "reason"\n'
)

# The fixed fields anchor the parse at the right-hand end, so a path may contain ":".
_ENTRY = re.compile(r"(?P<path>.+):(?P<rule>[^:\s]+):(?P<hash>[0-9a-f]{12}):(?P<line>\d+)")
_TABLE_HEADER = re.compile(rf"\s*\[\s*{TABLE}\s*\]\s*(?:#.*)?")
_ANY_HEADER = re.compile(r"\s*\[")


class AllowlistError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    path: str
    rule: str
    hash: str
    line: int = 0  # hint for humans; 0 for a whole-file entry
    reason: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.path, self.rule, self.hash)


def line_hash(line: str) -> str:
    """First 12 hex of SHA-256 over the line without trailing whitespace or line ending."""
    return hashlib.sha256(line.rstrip().encode("utf-8", "replace")).hexdigest()[:12]


def content_hash(data: bytes) -> str:
    """Hash for whole-file findings, which have no line to pin to."""
    return hashlib.sha256(data).hexdigest()[:12]


def parse_entry(text: str, reason: str = "") -> Entry:
    """Parse `path:rule:line-hash:line-number`. Raises ValueError if malformed."""
    m = _ENTRY.fullmatch(text)
    if m is None:
        raise ValueError(f"expected path:rule:line-hash:line-number, got {text!r}")
    return Entry(m["path"], m["rule"], m["hash"], int(m["line"]), reason)


def from_table(table: object) -> list[Entry]:
    """Entries from a parsed `[allow_lines]` table. Raises ValueError if malformed."""
    if not isinstance(table, dict):
        raise ValueError('must be a table of "path:rule:line-hash:line-number" = "reason"')
    entries = []
    for key, reason in table.items():
        if not isinstance(reason, str):
            raise ValueError(f"the reason for {key!r} must be a string")
        entries.append(parse_entry(key, reason))
    return entries


def format_entry(entry: Entry) -> str:
    """One TOML line. JSON string escaping is also valid TOML basic-string escaping."""
    key = f"{entry.path}:{entry.rule}:{entry.hash}:{entry.line}"
    reason = " ".join(entry.reason.split())
    return f"{json.dumps(key, ensure_ascii=False)} = {json.dumps(reason, ensure_ascii=False)}"


def keys(entries: Iterable[Entry]) -> set[tuple[str, str, str]]:
    return {entry.key for entry in entries}


def allows(allowed: set[tuple[str, str, str]], path: str, rule: str, digest: str) -> bool:
    return (path, rule, digest) in allowed or (path, "*", digest) in allowed


def stale(entries: Iterable[Entry], hashes_for: Callable[[str], set[str]]) -> list[Entry]:
    """Entries whose path is gone or whose hash matches nothing in the file.

    `hashes_for(path)` returns every live hash for a path, or an empty set if it is missing.
    """
    return [entry for entry in entries if entry.hash not in hashes_for(entry.path)]


# --- editing the table inside the config file -------------------------------

def _split(text: str) -> list[str]:
    return text.removesuffix("\n").split("\n") if text else []


def _section(lines: list[str]) -> tuple[int, int] | None:
    """Index of the `[allow_lines]` header and of the line after the table's last line."""
    for header, line in enumerate(lines):
        if _TABLE_HEADER.fullmatch(line):
            following = range(header + 1, len(lines))
            return header, next((i for i in following if _ANY_HEADER.match(lines[i])), len(lines))
    return None


def _line_key(line: str) -> tuple[str, str, str] | None:
    """The entry key a single table line defines, or None if it is not an entry."""
    try:
        (name,) = tomllib.loads(line)
        return parse_entry(name).key
    except ValueError:  # includes TOMLDecodeError and a line that is blank or a comment
        return None


def _write_checked(path: Path, old: str, new: str, expected: set, by_hand: str) -> None:
    """Write `new` only if it changes nothing but the table and the table holds `expected`."""
    try:
        before, after = tomllib.loads(old), tomllib.loads(new)
        before.pop(TABLE, None)
        safe = keys(from_table(after.pop(TABLE, {}))) == expected and before == after
    except ValueError:
        safe = False
    if not safe:
        raise AllowlistError(f"could not edit the [{TABLE}] table of {path.name} safely; {by_hand}")
    path.write_text(new, encoding="utf-8", newline="\n")


def append(path: Path, entries: Iterable[Entry]) -> int:
    """Add entries not already present to the config file at `path`. Returns how many."""
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    seen = keys(from_table(tomllib.loads(old).get(TABLE, {})))
    added = []
    for entry in entries:
        if entry.key not in seen:
            seen.add(entry.key)
            added.append(format_entry(entry))
    if not added:
        return 0
    lines = _split(old)
    section = _section(lines)
    if section is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines += [*_split(TABLE_COMMENT), f"[{TABLE}]", *added]
    else:
        header, at = section
        # Go after the last entry, not after comments that introduce the next table.
        while at > header + 1 and (not lines[at - 1].strip() or lines[at - 1].lstrip().startswith("#")):
            at -= 1
        lines[at:at] = added
    by_hand = "add these lines to it by hand:\n" + "\n".join(added)
    _write_checked(path, old, "\n".join(lines) + "\n", seen, by_hand)
    return len(added)


def prune(path: Path, hashes_for: Callable[[str], set[str]]) -> int:
    """Delete stale entries from the config file at `path`. Returns how many were removed."""
    if not path.exists():
        return 0
    old = path.read_text(encoding="utf-8")
    entries = from_table(tomllib.loads(old).get(TABLE, {}))
    dead = keys(stale(entries, hashes_for))
    if not dead:
        return 0
    lines = _split(old)
    header, end = _section(lines) or (len(lines), len(lines))
    kept = [line for line in lines[header + 1:end] if _line_key(line) not in dead]
    new = "\n".join(lines[:header + 1] + kept + lines[end:]) + "\n"
    by_hand = "remove its stale entries by hand:\n" + "\n".join(sorted(":".join(key) for key in dead))
    _write_checked(path, old, new, keys(entries) - dead, by_hand)
    return len(lines[header + 1:end]) - len(kept)
