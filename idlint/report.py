"""Render findings as text, JSON or SARIF. Matched values are masked unless asked otherwise."""

from __future__ import annotations

import json
from collections import Counter
from itertools import groupby

from . import __version__
from .config import FILENAME as CONFIG_FILE
from .rules import Rule
from .scanner import Finding

PER_RULE_LIMIT = 5  # findings shown per rule per file in text output


def mask(value: str) -> str:
    """First 2 and last 2 characters; 6 characters or fewer are fully masked."""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:2]}**…**{value[-2:]}"


def _display(finding: Finding, show_values: bool) -> str:
    if finding.label or not finding.value:
        return finding.label
    return finding.value if show_values else mask(finding.value)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def render_text(findings: list[Finding], *, show_values: bool = False, color: bool = False,
                staged: bool = False, files_scanned: int = 0, stale: int = 0) -> str:
    bold, red, reset = ("\x1b[1m", "\x1b[31m", "\x1b[0m") if color else ("", "", "")
    out = []
    if findings:
        width = max(len(f.rule) for f in findings) + 3
        position_width = max(7, max(len(f"{f.line}:{f.column}") for f in findings) + 2)
        files = 0
        for path, group in groupby(findings, key=lambda f: f.path):
            files += 1
            out.append(f"{bold}{path}{reset}")
            shown: Counter[str] = Counter()
            for f in group:
                shown[f.rule] += 1
                if shown[f.rule] > PER_RULE_LIMIT:
                    continue
                position = f"{f.line}:{f.column}" if f.line else "-"
                row = f"  {position:<{position_width}}{red}{f.rule}{reset}{' ' * (width - len(f.rule))}{_display(f, show_values)}"
                out.append(row.rstrip())
            more = [f"{count - PER_RULE_LIMIT} more {rule}" for rule, count in shown.items()
                    if count > PER_RULE_LIMIT]
            if more:
                out.append("  ... " + ", ".join(more))
        rules = len({f.rule for f in findings})
        out.append("")
        out.append(f"{_plural(len(findings), 'finding')}: {_plural(rules, 'rule')} fired in "
                   f"{_plural(files, 'file')}." + (" Commit blocked." if staged else ""))
        out.append('Fix the data, or run: idlint allow FILE:LINE --reason "..."')
    elif not staged:
        out.append(f"No findings in {_plural(files_scanned, 'file')}.")
    if stale:
        entries = "1 stale entry" if stale == 1 else f"{stale} stale entries"
        out.append(f"{entries} in {CONFIG_FILE}. Run: idlint prune")
    return "".join(line + "\n" for line in out)


def render_json(findings: list[Finding], *, show_values: bool = False,
                files_scanned: int = 0, stale: int = 0) -> str:
    items = []
    for f in findings:
        item = {"path": f.path, "line": f.line, "column": f.column, "rule": f.rule,
                "masked": f.label or mask(f.value), "line_hash": f.line_hash}
        if show_values:
            item["value"] = f.value
        items.append(item)
    summary = {
        "findings": len(findings),
        "files": len({f.path for f in findings}),
        "files_scanned": files_scanned,
        "rules": dict(Counter(f.rule for f in findings)),
        "stale_allow_entries": stale,
    }
    return json.dumps({"findings": items, "summary": summary}, indent=2, ensure_ascii=False) + "\n"


def render_sarif(findings: list[Finding], rules: dict[str, Rule], *, show_values: bool = False) -> str:
    results = []
    for f in findings:
        location = {"artifactLocation": {"uri": f.path}}
        if f.line:
            location["region"] = {"startLine": f.line, "startColumn": f.column}
        results.append({
            "ruleId": f.rule,
            "level": rules[f.rule].severity,
            "message": {"text": " ".join(filter(None, [f.rule, _display(f, show_values)]))},
            "locations": [{"physicalLocation": location}],
            "partialFingerprints": {"lineHash": f.line_hash},
        })
    fired = sorted({f.rule for f in findings})
    driver = {
        "name": "idlint",
        "version": __version__,
        "rules": [{"id": rule_id,
                   "shortDescription": {"text": rules[rule_id].description},
                   "defaultConfiguration": {"level": rules[rule_id].severity}} for rule_id in fired],
    }
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
