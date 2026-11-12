import os
import subprocess
import sys
from pathlib import Path

import pytest


def run_git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    return result.stdout.decode()


@pytest.fixture(autouse=True)
def isolated_git(monkeypatch, tmp_path_factory):
    """Keep the developer's git config, hooks and any enclosing hook environment out of tests."""
    empty = tmp_path_factory.mktemp("gitconfig") / "config"
    empty.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)
    # The installed hook calls `idlint`; make sure it resolves to this environment.
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"])


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """An empty git repository that is also the current directory."""
    root = tmp_path / "repo"
    root.mkdir()
    run_git(root, "init", "-q", "-b", "main")
    run_git(root, "config", "user.name", "Test")
    run_git(root, "config", "user.email", "test@localhost")
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def git(repo):
    return lambda *args: run_git(repo, *args)
