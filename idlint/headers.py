"""sensitive-column detection: CSV-style header rows and JSON object keys."""

from __future__ import annotations

import csv
import re

DEFAULT_NAMES = (
    "prolific_pid", "prolific_id", "participant_id", "worker_id", "assignment_id",
    "ip", "ip_address", "latitude", "longitude", "lat", "lng", "lon",
    "location_latitude", "location_longitude", "email", "recipient_email",
    "first_name", "last_name", "recipient_first_name", "recipient_last_name",
    "full_name", "phone", "address", "street", "zip", "postcode", "dob",
    "date_of_birth", "ssn", "user_agent", "device_id",
)

DELIMITERS = {".csv": ",", ".tsv": "\t", ".psv": "|"}
JSON_EXTENSIONS = frozenset({".json", ".jsonl", ".ndjson"})

_SEPARATORS = re.compile(r"[_\- ]")
_JSON_KEY = re.compile(r'"([^"\\]{1,64})"\s*:')


def normalize(name: str) -> str:
    """Lowercase and drop `_`, `-` and spaces, which also erases camelCase boundaries."""
    return _SEPARATORS.sub("", name).lower()


def header_hits(line: str, delimiter: str, names: frozenset[str]) -> list[tuple[int, str]]:
    """(1-based column, name) for each header field whose normalized name is in `names`."""
    try:
        fields = next(csv.reader([line], delimiter=delimiter), [])
    except csv.Error:  # a field over the csv module's size limit: not a header row
        return []
    hits = []
    position = 0
    for field in fields:
        name = field.strip()
        found = line.find(name, position) if name else -1
        if found >= 0:
            position = found + len(name)
            if normalize(name) in names:
                hits.append((found + 1, name))
    return hits


def json_key_hits(line: str, names: frozenset[str]) -> list[tuple[int, str]]:
    """(1-based column, key) for each JSON object key on the line that is in `names`."""
    return [(m.start(1) + 1, m.group(1)) for m in _JSON_KEY.finditer(line)
            if normalize(m.group(1)) in names]
