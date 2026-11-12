"""Scan one file's bytes and produce findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .allowlist import content_hash, line_hash
from .config import Config
from .headers import DELIMITERS, JSON_EXTENSIONS, header_hits, json_key_hits

_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
_INLINE_ALLOW = re.compile(r"idlint:allow(?:\[([^\]]*)\])?")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int  # 0 for a whole-file finding
    column: int
    rule: str
    value: str  # raw matched text; only shown with --show-values
    line_hash: str  # content hash for a whole-file finding
    label: str = ""  # display text that is safe to print, such as a header name


def is_binary(data: bytes) -> bool:
    """A NUL byte in the first 8 KB, unless the file is UTF-16 text."""
    return data[:2] not in _UTF16_BOMS and b"\0" in data[:8192]


def decode(data: bytes) -> str:
    if data[:2] in _UTF16_BOMS:  # Qualtrics exports can be UTF-16
        return data.decode("utf-16", "replace")
    return data.decode("utf-8-sig", "replace")


def file_hashes(data: bytes) -> set[str]:
    """Every hash an allowlist entry for this file could match."""
    hashes = {content_hash(data)}
    if not is_binary(data):
        hashes.update(line_hash(line) for line in decode(data).split("\n"))
    return hashes


def _inline_allowed(line: str) -> set[str]:
    """Rule ids allowed by `idlint:allow` comments on the line; `*` means all."""
    allowed = set()
    for m in _INLINE_ALLOW.finditer(line):
        if m.group(1) is None:
            allowed.add("*")
        else:
            allowed.update(name.strip() for name in m.group(1).split(","))
    return allowed


def scan_file(path: str, data: bytes, config: Config, suppress: bool = True) -> list[Finding]:
    """Findings for one file. `path` is repo-relative with forward slashes.

    With `suppress` off, path excludes, value allowlists and inline comments are ignored.
    """
    if suppress and config.path_excluded(path):
        return []

    def active(rule_id: str) -> bool:
        return rule_id in config.enabled and not (suppress and config.path_excluded(path, rule_id))

    def whole_file(rule_id: str) -> list[Finding]:
        return [Finding(path, 0, 0, rule_id, "", content_hash(data))] if active(rule_id) else []

    extension = PurePosixPath(path).suffix.lower()
    if extension in config.unscannable_extensions:
        return whole_file("unscannable-data-file")
    if is_binary(data):
        return []
    if len(data) > config.max_file_size:
        return whole_file("oversize-file")

    lines = decode(data).split("\n")
    hits = []  # (line number, column, rule id, value, label)
    for rule in config.rules.values():
        if rule.pattern is None or not active(rule.id):
            continue
        for number, line in enumerate(lines, 1):
            for m in rule.find(line):
                start, end = rule.span(m)
                hits.append((number, start + 1, rule.id, line[start:end], ""))
    if active("sensitive-column"):
        if extension in DELIMITERS:
            for column, name in header_hits(lines[0], DELIMITERS[extension], config.sensitive_names):
                hits.append((1, column, "sensitive-column", name, f'header "{name}"'))
        elif extension in JSON_EXTENSIONS:
            for number, line in enumerate(lines, 1):
                for column, name in json_key_hits(line, config.sensitive_names):
                    hits.append((number, column, "sensitive-column", name, f'key "{name}"'))

    hits.sort()
    findings = []
    current = 0  # line number the cached hash and inline comment belong to
    for number, column, rule_id, value, label in hits:
        if number != current:  # a long line can carry thousands of hits; hash it once
            current = number
            digest = line_hash(lines[number - 1])
            allowed = _inline_allowed(lines[number - 1]) if suppress else ()
        if suppress and config.value_allowed(rule_id, value):
            continue
        if "*" in allowed or rule_id in allowed:
            continue
        findings.append(Finding(path, number, column, rule_id, value, digest, label))
    return findings
