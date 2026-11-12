"""Load and validate `.idlint.toml`.

Unknown keys are errors, so a typo never silently disables a rule.
"""

from __future__ import annotations

import dataclasses
import functools
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import allowlist
from .headers import DEFAULT_NAMES, normalize
from .rules import BUILTIN_RULES, Rule

FILENAME = ".idlint.toml"
DEFAULT_MAX_FILE_SIZE = 5_000_000
UNSCANNABLE_EXTENSIONS = frozenset({
    ".xlsx", ".xls", ".sav", ".dta", ".rds", ".rdata", ".parquet", ".feather",
    ".pkl", ".pickle", ".sqlite", ".db", ".h5", ".mat", ".zip", ".gz",
})

_TOP_KEYS = {"exclude_paths", "max_file_size", "extra_unscannable_extensions", "rules", "rule", "custom_rule",
             allowlist.TABLE}
_RULE_KEYS = {"allow_values", "allow_patterns", "exclude_paths"}
_CUSTOM_KEYS = {"id", "description", "pattern", "require_on_line"}


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class RuleSettings:
    allow_values: frozenset[str] = frozenset()
    allow_patterns: tuple[re.Pattern, ...] = ()
    exclude_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    rules: dict[str, Rule]  # every known rule, built-in and custom
    enabled: frozenset[str]
    exclude_paths: tuple[str, ...] = ()
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    unscannable_extensions: frozenset[str] = UNSCANNABLE_EXTENSIONS
    sensitive_names: frozenset[str] = frozenset(normalize(name) for name in DEFAULT_NAMES)
    settings: dict[str, RuleSettings] = field(default_factory=dict)
    allow_lines: tuple[allowlist.Entry, ...] = ()  # the line allowlist

    def path_excluded(self, path: str, rule_id: str | None = None) -> bool:
        patterns = self.exclude_paths
        if rule_id is not None and rule_id in self.settings:
            patterns += self.settings[rule_id].exclude_paths
        return any(path_matches(path, pattern) for pattern in patterns)

    def value_allowed(self, rule_id: str, value: str) -> bool:
        settings = self.settings.get(rule_id)
        if settings is None:
            return False
        return value in settings.allow_values or any(p.search(value) for p in settings.allow_patterns)

    def select(self, only: Iterable[str] | None = None, skip: Iterable[str] | None = None) -> Config:
        """Override the enabled rules for one run (`--rules`, `--skip-rules`)."""
        enabled = self.enabled
        for ids in (only, skip):
            for rule_id in ids or ():
                if rule_id not in self.rules:
                    raise ConfigError(f"unknown rule: {rule_id}")
        if only is not None:
            enabled = frozenset(only)
        if skip is not None:
            enabled -= frozenset(skip)
        return dataclasses.replace(self, enabled=enabled)


@functools.lru_cache(maxsize=None)
def _glob_regex(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def path_matches(path: str, pattern: str) -> bool:
    """Glob match on a repo-relative path. `*` and `?` stay within one path segment,
    `**` crosses segments, and a pattern without `/` matches the file name at any depth."""
    target = path if "/" in pattern else path.rsplit("/", 1)[-1]
    return _glob_regex(pattern).fullmatch(target) is not None


def _check_keys(table: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"unknown key in {where}: {', '.join(unknown)}")


def _typed(table: dict, key: str, kind: type, where: str, default):
    value = table.get(key, default)
    if not isinstance(value, kind) or isinstance(value, bool) and kind is not bool:
        raise ConfigError(f"{where}{key} must be {kind.__name__}")
    return value


def _strings(table: dict, key: str, where: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{where}{key} must be a list of strings")
    return value


def _regex(pattern: str, where: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except re.error as error:
        raise ConfigError(f"{where}: invalid regex: {error}") from None


def parse(text: str) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"invalid TOML: {error}") from None
    _check_keys(data, _TOP_KEYS, "top level")

    rules = dict(BUILTIN_RULES)
    custom = data.get("custom_rule", [])
    if not isinstance(custom, list) or not all(isinstance(item, dict) for item in custom):
        raise ConfigError("custom_rule must be an array of tables ([[custom_rule]])")
    for item in custom:
        _check_keys(item, _CUSTOM_KEYS, "[[custom_rule]]")
        if "id" not in item or "pattern" not in item:
            raise ConfigError("[[custom_rule]] needs both id and pattern")
        rule_id = _typed(item, "id", str, "custom_rule.", "")
        where = f"custom_rule {rule_id}: "
        if rule_id in rules:
            raise ConfigError(f"{where}id is already in use")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", rule_id):
            raise ConfigError(f"{where}id may only contain letters, digits, '_', '.' and '-'")
        rules[rule_id] = Rule(
            id=rule_id,
            description=_typed(item, "description", str, where, "Custom rule"),
            pattern=_regex(_typed(item, "pattern", str, where, ""), where + "pattern"),
            require_on_line=tuple(word.lower() for word in _strings(item, "require_on_line", where)),
        )

    enabled = {rule.id for rule in rules.values() if rule.default_on}
    for rule_id, on in _typed(data, "rules", dict, "", {}).items():
        if rule_id not in rules:
            raise ConfigError(f"unknown rule in [rules]: {rule_id}")
        if not isinstance(on, bool):
            raise ConfigError(f"rules.{rule_id} must be true or false")
        (enabled.add if on else enabled.discard)(rule_id)

    names = {normalize(name) for name in DEFAULT_NAMES}
    settings = {}
    for rule_id, table in _typed(data, "rule", dict, "", {}).items():
        where = f"rule.{rule_id}."
        if rule_id not in rules:
            raise ConfigError(f"unknown rule: [rule.{rule_id}]")
        if not isinstance(table, dict):
            raise ConfigError(f"[rule.{rule_id}] must be a table")
        allowed = set(_RULE_KEYS)
        if rules[rule_id].pattern is not None:
            allowed.add("pattern")
        if rule_id == "sensitive-column":
            allowed |= {"add_names", "remove_names"}
        _check_keys(table, allowed, f"[rule.{rule_id}]")
        if "pattern" in table:
            pattern = _regex(_typed(table, "pattern", str, where, ""), where + "pattern")
            rules[rule_id] = dataclasses.replace(rules[rule_id], pattern=pattern)
        names |= {normalize(name) for name in _strings(table, "add_names", where)}
        names -= {normalize(name) for name in _strings(table, "remove_names", where)}
        settings[rule_id] = RuleSettings(
            allow_values=frozenset(_strings(table, "allow_values", where)),
            allow_patterns=tuple(_regex(p, where + "allow_patterns")
                                 for p in _strings(table, "allow_patterns", where)),
            exclude_paths=tuple(_strings(table, "exclude_paths", where)),
        )

    try:
        allow_lines = tuple(allowlist.from_table(data.get(allowlist.TABLE, {})))
    except ValueError as error:
        raise ConfigError(f"{allowlist.TABLE}: {error}") from None

    extra = {ext.lower() if ext.startswith(".") else "." + ext.lower()
             for ext in _strings(data, "extra_unscannable_extensions", "")}
    return Config(
        rules=rules,
        enabled=frozenset(enabled),
        exclude_paths=tuple(_strings(data, "exclude_paths", "")),
        max_file_size=_typed(data, "max_file_size", int, "", DEFAULT_MAX_FILE_SIZE),
        unscannable_extensions=UNSCANNABLE_EXTENSIONS | extra,
        sensitive_names=frozenset(names),
        settings=settings,
        allow_lines=allow_lines,
    )


def load(root: Path) -> Config:
    path = root / FILENAME
    if not path.exists():
        return parse("")
    try:
        return parse(path.read_text(encoding="utf-8"))
    except ConfigError as error:
        raise ConfigError(f"{FILENAME}: {error}") from None
