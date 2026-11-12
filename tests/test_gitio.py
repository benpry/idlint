import pytest

from idlint import gitio


def test_repo_root_from_subdirectory_and_outside(repo, tmp_path):
    (repo / "sub").mkdir()
    assert gitio.repo_root(repo / "sub") == repo.resolve()
    assert gitio.repo_root(tmp_path) is None


def test_staged_files_and_content_come_from_the_index(repo, git):
    (repo / "kept.txt").write_text("old\n")
    (repo / "gone.txt").write_text("x\n")
    git("add", ".")
    git("commit", "-qm", "init")
    (repo / "kept.txt").write_text("staged\n")
    (repo / "new file é.txt").write_text("new\n")
    git("add", ".")
    git("rm", "-q", "--cached", "gone.txt")
    (repo / "kept.txt").write_text("working tree\n")
    (repo / "unstaged.txt").write_text("x\n")
    assert sorted(gitio.staged_files(repo)) == ["kept.txt", "new file é.txt"]
    assert gitio.read_staged(repo, "kept.txt") == b"staged\n"
    assert gitio.read_staged(repo, "new file é.txt") == b"new\n"


def test_staged_files_before_the_first_commit(repo, git):
    (repo / "a.txt").write_text("a\n")
    git("add", "a.txt")
    assert gitio.staged_files(repo) == ["a.txt"]


def test_gitlinks_are_not_files(repo, git):
    (repo / "a.txt").write_text("a\n")
    git("add", "a.txt")
    git("commit", "-qm", "init")
    sha = git("rev-parse", "HEAD").strip()
    git("update-index", "--add", "--cacheinfo", f"160000,{sha},vendor/sub")
    assert gitio.staged_files(repo) == []
    git("commit", "-qm", "add submodule link")
    assert gitio.tracked_files(repo) == ["a.txt"]


def test_tracked_files_and_content_come_from_head(repo, git):
    (repo / "dir").mkdir()
    (repo / "dir" / "a.txt").write_text("committed\n")
    git("add", ".")
    git("commit", "-qm", "init")
    (repo / "dir" / "a.txt").write_text("changed\n")
    (repo / "b.txt").write_text("staged only\n")
    git("add", ".")
    assert gitio.tracked_files(repo) == ["dir/a.txt"]
    assert gitio.read_head(repo, "dir/a.txt") == b"committed\n"


def test_tracked_files_without_commits_is_an_error(repo):
    with pytest.raises(gitio.GitError):
        gitio.tracked_files(repo)


def test_worktree_files_respect_gitignore(repo, git):
    (repo / ".gitignore").write_text("ignored/\n*.tmp\n")
    for name in ("a.txt", "x.tmp", "ignored/b.txt", "sub/c.txt", "sub/deep/d.txt"):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n")
    git("add", "a.txt")
    git("commit", "-qm", "init")
    (repo / "a.txt").unlink()  # tracked but deleted from the working tree
    (repo / "e.txt").write_text("untracked\n")
    assert gitio.worktree_files(repo, ["."]) == [".gitignore", "e.txt", "sub/c.txt", "sub/deep/d.txt"]
    assert gitio.worktree_files(repo, ["sub/deep", "e.txt"]) == ["e.txt", "sub/deep/d.txt"]
    everything = gitio.worktree_files(repo, ["."], use_git=False)
    assert everything == [".gitignore", "e.txt", "ignored/b.txt", "sub/c.txt", "sub/deep/d.txt", "x.tmp"]


def test_a_file_named_explicitly_is_scanned_even_if_ignored(repo):
    (repo / ".gitignore").write_text("raw/\n")
    (repo / "raw").mkdir()
    (repo / "raw" / "export.csv").write_text("x\n")
    assert gitio.worktree_files(repo, ["raw/export.csv"]) == ["raw/export.csv"]
    assert gitio.worktree_files(repo, ["raw"]) == []


def test_hooks_dir_honours_core_hookspath(repo, git):
    assert gitio.hooks_dir(repo) == repo.resolve() / ".git" / "hooks"
    git("config", "core.hooksPath", ".githooks")
    assert gitio.hooks_dir(repo) == repo.resolve() / ".githooks"
