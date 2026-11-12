"""Everything that shells out to git: listing and reading staged, tracked and working-tree files."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


class GitError(Exception):
    pass


def _git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(["git", "--literal-pathspecs", *args], cwd=root, capture_output=True)
    except FileNotFoundError:
        raise GitError("git is not installed or not on PATH") from None
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {args[0]} failed: {message}")
    return result.stdout


def _names(output: bytes) -> list[str]:
    """Split NUL-separated git output into paths."""
    return [name.decode("utf-8", "surrogateescape") for name in output.split(b"\0") if name]


def repo_root(cwd: Path) -> Path | None:
    """Top level of the repository containing `cwd`, or None outside a repository."""
    try:
        return Path(_git(cwd, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    except GitError:
        return None


def staged_files(root: Path) -> list[str]:
    """Files added, copied, modified or renamed in the index."""
    names = _names(_git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))
    if not names:
        return []
    # A submodule appears in the index as a gitlink (mode 160000), which has no content to read.
    gitlinks = {entry.split("\t", 1)[1] for entry in _names(_git(root, "ls-files", "-s", "-z"))
                if entry.startswith("160000 ")}
    return [name for name in names if name not in gitlinks]


def read_staged(root: Path, path: str) -> bytes:
    return _git(root, "show", f":0:{path}")


def tracked_files(root: Path) -> list[str]:
    """Every file in the HEAD commit."""
    entries = _names(_git(root, "ls-tree", "-r", "-z", "HEAD"))
    return [entry.split("\t", 1)[1] for entry in entries if entry.split(" ", 2)[1] == "blob"]


def read_head(root: Path, path: str) -> bytes:
    return _git(root, "show", f"HEAD:{path}")


def worktree_files(root: Path, paths: list[str], use_git: bool = True) -> list[str]:
    """Files under `paths` (repo-relative) in the working tree.

    With `use_git`, directories are listed through git so `.gitignore` applies. A path that
    names a file is always included, because asking for it by name overrides ignore rules.
    """
    names = set()
    for path in paths:
        full = root / path
        if full.is_file():
            names.add(Path(path).as_posix())
        elif use_git:
            names.update(_names(_git(root, "ls-files", "-z", "--cached", "--others",
                                     "--exclude-standard", "--", path)))
        else:
            for directory, subdirectories, files in os.walk(full):
                subdirectories[:] = [d for d in subdirectories if d != ".git"]
                names.update((Path(directory) / name).relative_to(root).as_posix() for name in files)
    return sorted(name for name in names if (root / name).is_file())


def hooks_dir(root: Path) -> Path:
    """The hooks directory, which is `core.hooksPath` when that is set."""
    return (root / _git(root, "rev-parse", "--git-path", "hooks").decode().strip()).resolve()
