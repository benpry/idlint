"""Command-line interface: argument parsing and the subcommands."""

from __future__ import annotations

import argparse
import dataclasses
import functools
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Callable, Iterable

from . import __version__, allowlist, config, gitio, report, scanner
from .allowlist import Entry
from .scanner import Finding

HOOK_COMMAND = "idlint scan --staged"
HOOK_SCRIPT = f"#!/bin/sh\n# Installed by `idlint install-hook`.\nexec {HOOK_COMMAND}\n"

STARTER_CONFIG = r"""# idlint configuration. Every setting is optional; an unknown key is an error.
# Run `idlint rules` to list rule IDs.

# Paths that are never scanned. `*` stays within one directory, `**` crosses directories,
# and a pattern without `/` matches a file name at any depth.
# exclude_paths = ["docs/**", "*.lock"]

# Text files above this many bytes are reported as oversize-file instead of being scanned.
# max_file_size = 5_000_000

# More extensions to report as unscannable-data-file.
# extra_unscannable_extensions = [".jld2"]

# Turn built-in rules on or off.
# [rules]
# us-zip = true
# mac-address = false

# Tune a rule: allow known values, or skip the rule for some paths.
# [rule.ipv4]
# allow_values = ["198.51.100.20"]
# allow_patterns = ['^198\.51\.']
# exclude_paths = ["infra/**"]

# Replace a built-in pattern, for example after checking it against a real export.
# [rule.prolific-id]
# pattern = '\b[0-9a-f]{24}\b'

# Change the column names that sensitive-column looks for.
# [rule.sensitive-column]
# add_names = ["sona_id", "netid"]
# remove_names = ["address"]

# Define a new rule: a regex plus an optional keyword that must be on the same line.
# [[custom_rule]]
# id = "sona-id"
# description = "SONA participant code"
# pattern = '\bSONA-\d{5}\b'
# require_on_line = ["sona"]

""" + allowlist.TABLE_COMMENT + f"[{allowlist.TABLE}]\n"


class UsageError(Exception):
    pass


def _root() -> tuple[Path, bool]:
    """The repository root, or the current directory when not in a repository."""
    cwd = Path.cwd().resolve()
    root = gitio.repo_root(cwd)
    return (root, True) if root else (cwd, False)


def _relative(root: Path, path: str) -> str:
    """A user-supplied path as a forward-slash path relative to the root."""
    full = Path(path).resolve()
    if not full.exists():
        raise UsageError(f"no such file or directory: {path}")
    try:
        return full.relative_to(root).as_posix()
    except ValueError:
        raise UsageError(f"{path} is outside {root}") from None


def _hashes_for(root: Path) -> Callable[[str], set[str]]:
    """Live allowlist hashes of a working-tree file, empty if the file is gone."""
    @functools.lru_cache(maxsize=None)
    def hashes(path: str) -> set[str]:
        try:
            return scanner.file_hashes((root / path).read_bytes())
        except OSError:
            return set()
    return hashes


def _scan(files: Iterable[tuple[str, bytes]], cfg: config.Config, allowed: set, suppress: bool = True
          ) -> tuple[list[Finding], int]:
    """Scan (path, content) pairs. Returns unsuppressed findings and the number of files read."""
    findings, count = [], 0
    for path, data in files:
        count += 1
        for finding in scanner.scan_file(path, data, cfg, suppress):
            if not (suppress and allowlist.allows(allowed, finding.path, finding.rule, finding.line_hash)):
                findings.append(finding)
    return findings, count


def _worktree(root: Path, paths: list[str], use_git: bool) -> Iterable[tuple[str, bytes]]:
    for name in gitio.worktree_files(root, paths, use_git):
        yield name, (root / name).read_bytes()


def _ids(value: str | None) -> list[str] | None:
    return None if value is None else [item.strip() for item in value.split(",") if item.strip()]


def _entries(count: int) -> str:
    return "1 entry" if count == 1 else f"{count} entries"


def cmd_scan(args: argparse.Namespace) -> int:
    root, in_repo = _root()
    cfg = config.load(root).select(only=_ids(args.rules), skip=_ids(args.skip_rules))
    if args.max_file_size is not None:
        cfg = dataclasses.replace(cfg, max_file_size=args.max_file_size)

    if args.staged or args.tracked:
        if args.paths:
            raise UsageError("--staged and --tracked do not take paths")
        if not in_repo:
            raise UsageError("not inside a git repository")
        names, read = ((gitio.staged_files(root), gitio.read_staged) if args.staged
                       else (gitio.tracked_files(root), gitio.read_head))
        files = ((name, read(root, name)) for name in names)
    else:
        paths = [_relative(root, path) for path in args.paths] or ["."]
        files = _worktree(root, paths, use_git=in_repo and not args.no_gitignore)

    findings, scanned = _scan(files, cfg, allowlist.keys(cfg.allow_lines), suppress=not args.no_allowlist)
    stale = len(allowlist.stale(cfg.allow_lines, _hashes_for(root)))

    if args.format == "json":
        output = report.render_json(findings, show_values=args.show_values, files_scanned=scanned, stale=stale)
    elif args.format == "sarif":
        output = report.render_sarif(findings, cfg.rules, show_values=args.show_values)
    else:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        output = report.render_text(findings, show_values=args.show_values, color=color,
                                    staged=args.staged, files_scanned=scanned, stale=stale)
    sys.stdout.write(output)
    return 1 if findings else 0


def cmd_allow(args: argparse.Namespace) -> int:
    root, in_repo = _root()
    cfg = config.load(root)
    if args.all:
        if args.target or args.rule:
            raise UsageError("--all takes no FILE:LINE or --rule")
        existing = allowlist.keys(cfg.allow_lines)
        findings, _ = _scan(_worktree(root, ["."], use_git=in_repo), cfg, existing)
        new = [Entry(f.path, f.rule, f.line_hash, f.line, args.reason) for f in findings]
    else:
        if not args.target:
            raise UsageError("give FILE:LINE, or FILE for a whole-file finding, or --all")
        name, colon, number = args.target.rpartition(":")
        if not (colon and number.isdigit()):
            name, number = args.target, "0"
        path, line = _relative(root, name), int(number)
        data = (root / path).read_bytes()
        if args.rule == "*":
            lines = scanner.decode(data).split("\n")
            if line > len(lines):
                raise UsageError(f"{path} has no line {line}")
            digest = allowlist.line_hash(lines[line - 1]) if line else allowlist.content_hash(data)
            new = [Entry(path, "*", digest, line, args.reason)]
        else:
            if args.rule is not None and args.rule not in cfg.rules:
                raise UsageError(f"unknown rule: {args.rule}")
            new = [Entry(f.path, f.rule, f.line_hash, f.line, args.reason)
                   for f in scanner.scan_file(path, data, cfg)
                   if f.line == line and args.rule in (None, f.rule)]
            if not new:
                raise UsageError(f"no findings to allow on {args.target}")
    added = allowlist.append(root / config.FILENAME, new)
    print(f"Added {_entries(added)} to {config.FILENAME}")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    root, _ = _root()
    config.load(root)  # report a broken config as a config error before editing it
    removed = allowlist.prune(root / config.FILENAME, _hashes_for(root))
    print(f"Removed {'1 stale entry' if removed == 1 else f'{removed} stale entries'} from {config.FILENAME}")
    return 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    root, in_repo = _root()
    if not in_repo:
        raise UsageError("not inside a git repository")
    hook = gitio.hooks_dir(root) / "pre-commit"
    if hook.exists() and not args.force:
        if not args.append:
            raise UsageError(f"{hook} already exists; use --append to add idlint to it or --force to replace it")
        text = hook.read_text(encoding="utf-8")
        if HOOK_COMMAND in text:
            print(f"{hook} already runs idlint")
            return 0
        first_line = text.split("\n", 1)[0]
        if first_line.startswith("#!") and not re.search(r"sh\b", first_line):
            raise UsageError(f"{hook} is not a shell script; add `{HOOK_COMMAND}` to it by hand")
        hook.write_text(text.rstrip("\n") + f"\n{HOOK_COMMAND} || exit $?\n", encoding="utf-8", newline="\n")
    else:
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text(HOOK_SCRIPT, encoding="utf-8", newline="\n")
        hook.chmod(0o755)
    print(f"Installed pre-commit hook at {hook}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    root, _ = _root()
    rules = config.load(root).rules.values()
    width = max(len(rule.id) for rule in rules) + 2
    print(f"{'RULE':<{width}}{'SEVERITY':<10}{'DEFAULT':<9}DESCRIPTION")
    for rule in rules:
        print(f"{rule.id:<{width}}{rule.severity:<10}{'on' if rule.default_on else 'off':<9}{rule.description}")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    root, _ = _root()
    path = root / config.FILENAME
    if path.exists():
        raise UsageError(f"{path} already exists")
    path.write_text(STARTER_CONFIG, encoding="utf-8", newline="\n")
    print(f"Wrote {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="idlint", description="Block git commits that contain participant PII.")
    parser.add_argument("--version", action="version", version=f"idlint {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = commands.add_parser("scan", help="scan files for PII")
    scan.add_argument("paths", nargs="*", metavar="PATHS",
                      help="files or directories in the working tree (default: the repo root)")
    source = scan.add_mutually_exclusive_group()
    source.add_argument("--staged", action="store_true", help="scan the staged content of added or modified files")
    source.add_argument("--tracked", action="store_true", help="scan every tracked file at HEAD")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--rules", metavar="ID,ID", help="run only these rules")
    scan.add_argument("--skip-rules", metavar="ID,ID", help="do not run these rules")
    scan.add_argument("--show-values", action="store_true", help="print matched text unmasked")
    scan.add_argument("--no-allowlist", action="store_true",
                      help="report everything, including suppressed findings")
    scan.add_argument("--no-gitignore", action="store_true", help="also scan files ignored by git")
    scan.add_argument("--max-file-size", type=int, metavar="BYTES",
                      help=f"report larger text files as oversize-file (default {config.DEFAULT_MAX_FILE_SIZE})")
    scan.set_defaults(func=cmd_scan)

    allow = commands.add_parser("allow", help="add suppressions to the [allow_lines] table of .idlint.toml")
    allow.add_argument("target", nargs="?", metavar="FILE:LINE",
                       help="line whose findings to allow; FILE alone for a whole-file finding")
    allow.add_argument("--all", action="store_true", help="allow every current finding (baseline)")
    allow.add_argument("--rule", metavar="ID", help="allow only this rule; `*` covers every rule on the line")
    allow.add_argument("--reason", default="", metavar="TEXT", help="why this is not PII")
    allow.set_defaults(func=cmd_allow)

    prune = commands.add_parser("prune", help="remove suppressions that no longer match any line")
    prune.set_defaults(func=cmd_prune)

    hook = commands.add_parser("install-hook", help="install the git pre-commit hook")
    existing = hook.add_mutually_exclusive_group()
    existing.add_argument("--force", action="store_true", help="replace an existing hook")
    existing.add_argument("--append", action="store_true", help="add idlint to an existing shell hook")
    hook.set_defaults(func=cmd_install_hook)

    rules = commands.add_parser("rules", help="list rules")
    rules.set_defaults(func=cmd_rules)

    init = commands.add_parser("init", help="write a commented starter .idlint.toml")
    init.set_defaults(func=cmd_init)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):  # a path the console cannot encode must not crash the scan
            stream.reconfigure(errors="replace")
    try:
        return args.func(args)
    except (UsageError, config.ConfigError, allowlist.AllowlistError, gitio.GitError, OSError) as error:
        print(f"idlint: error: {error}", file=sys.stderr)
    except Exception:  # a scan error must never exit 0
        traceback.print_exc()
    return 2
