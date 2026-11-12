import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from samples import EMAIL, OTHER_IP, PUBLIC_IP

from idlint import cli, config

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def run(capsys):
    def run(*args):
        code = cli.main([str(arg) for arg in args])
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    return run


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, newline="")
    return path


# --- scan: exit codes and modes ---------------------------------------------

def test_clean_scan_exits_0_and_findings_exit_1(repo, run):
    write(repo, "a.txt", "nothing here\n")
    assert run("scan") == (0, "No findings in 1 file.\n", "")
    write(repo, "b.txt", f"host {PUBLIC_IP}\n")
    code, out, _ = run("scan")
    assert code == 1
    assert out.splitlines()[0] == "b.txt"
    assert "1 finding: 1 rule fired in 1 file." in out


def test_usage_errors_exit_2(repo, run, capsys):
    for args in (["scan", "--format", "xml"], ["scan", "--staged", "--tracked"], ["nonsense"], []):
        with pytest.raises(SystemExit) as error:
            cli.main(args)
        assert error.value.code == 2
    capsys.readouterr()
    assert run("scan", "missing.csv")[0] == 2
    assert run("scan", "--staged", "a.txt")[0] == 2
    assert run("scan", "--rules", "nope")[0] == 2


def test_unknown_config_key_exits_2(repo, run):
    write(repo, ".idlint.toml", "exclude_path = ['docs/**']\n")
    write(repo, "a.txt", "clean\n")
    code, out, err = run("scan")
    assert code == 2
    assert "exclude_path" in err


def test_malformed_allowlist_exits_2(repo, run):
    write(repo, ".idlint.toml", '[allow_lines]\n"garbage" = ""\n')
    code, _, err = run("scan")
    assert code == 2 and "allow_lines" in err


def test_staged_scan_reads_the_index_not_the_working_tree(repo, git, run):
    # Staged with a finding, then reverted in the working tree: still reported.
    reverted = write(repo, "reverted.txt", f"{PUBLIC_IP}\n")
    # Clean when staged, finding added only in the working tree: ignored.
    unstaged = write(repo, "unstaged.txt", "clean\n")
    git("add", ".")
    reverted.write_text("clean\n")
    unstaged.write_text(f"{OTHER_IP}\n")
    code, out, _ = run("scan", "--staged", "--show-values")
    assert code == 1
    assert "reverted.txt" in out and PUBLIC_IP in out
    assert "unstaged.txt" not in out and OTHER_IP not in out
    assert "Commit blocked." in out


def test_staged_scan_with_nothing_staged_is_silent(repo, run):
    assert run("scan", "--staged") == (0, "", "")


def test_tracked_scan_reads_head(repo, git, run):
    write(repo, "old.txt", f"{PUBLIC_IP}\n")
    git("add", ".")
    git("commit", "-qm", "init")
    write(repo, "old.txt", "clean now\n")
    write(repo, "new.txt", f"{OTHER_IP}\n")
    code, out, _ = run("scan", "--tracked")
    assert code == 1
    assert "old.txt" in out and "new.txt" not in out


def test_scan_paths_and_gitignore(repo, run):
    write(repo, ".gitignore", "raw/\n")
    write(repo, "raw/export.csv", f"x\n{PUBLIC_IP}\n")
    write(repo, "src/a.txt", f"{OTHER_IP}\n")
    assert run("scan")[1].splitlines()[0] == "src/a.txt"
    assert "raw/export.csv" not in run("scan")[1]
    assert "raw/export.csv" in run("scan", "--no-gitignore")[1]
    assert "src/a.txt" not in run("scan", "raw/export.csv")[1]
    os.chdir(repo / "src")
    assert run("scan", "a.txt")[1].splitlines()[0] == "src/a.txt"


def test_scan_outside_a_git_repository(tmp_path, monkeypatch, run):
    monkeypatch.chdir(tmp_path)
    write(tmp_path, "export/a.csv", f"x\n{PUBLIC_IP}\n")
    code, out, _ = run("scan")
    assert code == 1 and "export/a.csv" in out
    assert run("scan", "--staged")[0] == 2


# --- scan: detection behaviour ----------------------------------------------

def test_csv_header_flags_only_ipaddress(repo, run):
    write(repo, "d.csv", "Name,IPAddress,Score\na,b,1\n")
    code, out, _ = run("scan", "--format", "json")
    assert code == 1
    assert [(f["rule"], f["masked"]) for f in json.loads(out)["findings"]] == [
        ("sensitive-column", 'header "IPAddress"')]


def test_staged_xlsx_is_flagged_and_blocks(repo, git, run):
    write(repo, "data/responses.xlsx", b"PK\x03\x04binary")
    git("add", ".")
    code, out, _ = run("scan", "--staged")
    assert code == 1
    assert out.splitlines()[:2] == ["data/responses.xlsx", "  -      unscannable-data-file"]


def test_inline_allow_for_one_rule(repo, run):
    write(repo, "a.py", f'x = "{PUBLIC_IP} {EMAIL}"  # idlint:allow[ipv4]\n')
    code, out, _ = run("scan", "--format", "json")
    assert [f["rule"] for f in json.loads(out)["findings"]] == ["email"]


def test_values_are_masked_unless_show_values(repo, run):
    write(repo, "a.txt", f"{PUBLIC_IP} {EMAIL}\n")
    for fmt in ("text", "json", "sarif"):
        masked = run("scan", "--format", fmt)[1]
        assert PUBLIC_IP not in masked and EMAIL not in masked
        shown = run("scan", "--format", fmt, "--show-values")[1]
        assert PUBLIC_IP in shown and EMAIL in shown


def test_rules_and_skip_rules_flags(repo, run):
    write(repo, "a.txt", f"{PUBLIC_IP} {EMAIL} zip 08544\n")

    def fired(*flags):
        return sorted(json.loads(run("scan", "--format", "json", *flags)[1])["summary"]["rules"])

    assert fired() == ["email", "ipv4"]
    assert fired("--skip-rules", "email") == ["ipv4"]
    assert fired("--rules", "us-zip,email") == ["email", "us-zip"]


def test_max_file_size_flag_produces_oversize_finding(repo, run):
    write(repo, "a.csv", "x\n" * 100)
    code, out, _ = run("scan", "--max-file-size", "50")
    assert code == 1 and "oversize-file" in out
    write(repo, ".idlint.toml", "max_file_size = 50\n")
    assert run("scan", "--max-file-size", "5000")[0] == 0  # flag beats config


def test_sarif_output(repo, run):
    write(repo, "a.txt", f"{PUBLIC_IP}\n")
    code, out, _ = run("scan", "--format", "sarif")
    assert code == 1
    assert json.loads(out)["runs"][0]["results"][0]["ruleId"] == "ipv4"


def test_custom_rule_from_config(repo, run):
    write(repo, ".idlint.toml", "[[custom_rule]]\nid = 'sona-id'\npattern = 'SONA-[0-9]{5}'\n")
    write(repo, "a.txt", "SONA-12345\n")
    assert "sona-id" in run("scan")[1]


# --- allowlist ----------------------------------------------------------------

def test_allow_then_scan_passes_and_survives_line_shifts(repo, run):
    write(repo, "d.txt", f"header\n{PUBLIC_IP}\n")
    assert run("scan")[0] == 1
    code, out, _ = run("allow", "d.txt:2", "--reason", "lab server")
    assert code == 0 and "1 entry" in out
    (entry,) = config.load(repo).allow_lines
    assert (entry.path, entry.rule, entry.line, entry.reason) == ("d.txt", "ipv4", 2, "lab server")
    assert PUBLIC_IP not in (repo / ".idlint.toml").read_text()
    assert run("scan")[0] == 0

    write(repo, "d.txt", "new line\n" * 10 + f"header\n{PUBLIC_IP}\n")
    assert run("scan")[0] == 0  # ten lines inserted above

    write(repo, "d.txt", "header\r\n" + PUBLIC_IP + "\r\n")
    assert run("scan")[0] == 0  # CRLF checkout of the same content

    write(repo, "d.txt", f"header\n{PUBLIC_IP[:-1]}8\n")
    code, out, _ = run("scan")
    assert code == 1  # one character changed
    assert "1 stale entry in .idlint.toml" in out


def test_allow_keeps_the_existing_config(repo, run):
    settings = "# lab settings\n[rules]\nemail = false  # we publish contact addresses\n"
    write(repo, ".idlint.toml", settings)
    write(repo, "d.txt", f"{PUBLIC_IP} {EMAIL}\n")
    code, out, _ = run("allow", "d.txt:1", "--reason", "lab server")
    assert code == 0 and "1 entry to .idlint.toml" in out
    text = (repo / ".idlint.toml").read_text()
    assert text.startswith(settings) and "[allow_lines]" in text
    assert run("scan")[0] == 0  # ipv4 allowed by the new entry, email still off
    assert not (repo / ".idlint-allow").exists()


def test_init_then_allow_fills_the_starter_table(repo, run):
    run("init")
    write(repo, "d.txt", f"{PUBLIC_IP}\n")
    assert run("allow", "d.txt:1")[0] == 0
    assert (repo / ".idlint.toml").read_text().count("[allow_lines]") == 1
    assert run("scan")[0] == 0


def test_prune_removes_entry_after_the_line_is_deleted(repo, run):
    write(repo, "d.txt", f"{PUBLIC_IP}\nkeep {OTHER_IP}\n")
    run("allow", "d.txt:1")
    run("allow", "d.txt:2")
    write(repo, "d.txt", f"keep {OTHER_IP}\n")
    code, out, _ = run("prune")
    assert code == 0 and "1 stale entry" in out
    assert [e.line for e in config.load(repo).allow_lines] == [2]
    assert run("scan") == (0, "No findings in 2 files.\n", "")


def test_allow_with_rule_filter_and_wildcard(repo, run):
    write(repo, "d.txt", f"{PUBLIC_IP} {EMAIL}\n")
    run("allow", "d.txt:1", "--rule", "ipv4")
    assert json.loads(run("scan", "--format", "json")[1])["summary"]["rules"] == {"email": 1}
    run("allow", "d.txt:1", "--rule", "*")
    assert run("scan")[0] == 0
    assert [e.rule for e in config.load(repo).allow_lines] == ["ipv4", "*"]


def test_allow_errors(repo, run):
    write(repo, "d.txt", f"clean\n{PUBLIC_IP}\n")
    assert run("allow", "d.txt:1")[0] == 2  # nothing to allow on that line
    assert run("allow", "d.txt:2", "--rule", "email")[0] == 2
    assert run("allow", "d.txt:2", "--rule", "nope")[0] == 2
    assert run("allow", "d.txt:99", "--rule", "*")[0] == 2
    assert run("allow", "missing.txt:1")[0] == 2
    assert run("allow")[0] == 2
    assert run("allow", "--all", "d.txt:2")[0] == 2
    assert not (repo / ".idlint.toml").exists()


def test_allow_all_creates_a_baseline(repo, run):
    write(repo, "a.csv", f"IPAddress,x\n{PUBLIC_IP},1\n{OTHER_IP},2\n")
    write(repo, "data/r.xlsx", b"PK\x03\x04binary")
    assert run("scan")[0] == 1
    code, out, _ = run("allow", "--all", "--reason", "baseline")
    assert code == 0 and "4 entries" in out
    assert run("scan")[0] == 0
    write(repo, "b.txt", f"{EMAIL}\n")
    assert run("scan")[0] == 1  # new findings are still reported
    assert "a.csv" in run("scan", "--no-allowlist")[1]


def test_allow_whole_file_finding_expires_when_the_file_changes(repo, run):
    write(repo, "data/r.xlsx", b"PK\x03\x04binary")
    assert run("allow", "data/r.xlsx", "--reason", "codebook, no participant data")[0] == 0
    assert run("scan")[0] == 0
    write(repo, "data/r.xlsx", b"PK\x03\x04different")
    assert run("scan")[0] == 1


def test_no_allowlist_reports_suppressed_findings(repo, run):
    write(repo, ".idlint.toml", 'exclude_paths = ["docs/**"]\n')
    write(repo, "docs/a.md", f"{PUBLIC_IP}\n")
    write(repo, "b.py", f'x = "{OTHER_IP}"  # idlint:allow\n')
    assert run("scan")[0] == 0
    code, out, _ = run("scan", "--no-allowlist")
    assert code == 1 and "docs/a.md" in out and "b.py" in out


# --- other subcommands ----------------------------------------------------------

def test_rules_lists_every_rule(repo, run):
    write(repo, ".idlint.toml", "[[custom_rule]]\nid = 'sona-id'\npattern = 'x'\n")
    code, out, _ = run("rules")
    assert code == 0
    rows = {line.split()[0]: line.split() for line in out.splitlines()[1:]}
    assert rows["ipv4"][1:3] == ["error", "on"]
    assert rows["us-zip"][1:3] == ["error", "off"]
    assert rows["oversize-file"][1:3] == ["warning", "on"]
    assert {"sensitive-column", "unscannable-data-file", "sona-id"} <= set(rows)


def test_init_writes_a_starter_config_that_changes_nothing(repo, run):
    assert run("init")[0] == 0
    assert (repo / ".idlint.toml").read_text().startswith("#")
    assert config.load(repo) == config.parse("")
    assert run("init")[0] == 2  # will not overwrite


def test_install_hook_writes_executable_script(repo, run):
    assert run("install-hook")[0] == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    text = hook.read_text()
    assert text.startswith("#!/bin/sh\n") and "idlint scan --staged" in text
    assert os.name == "nt" or os.access(hook, os.X_OK)


def test_install_hook_refuses_to_overwrite_without_force(repo, run):
    hook = write(repo, ".git/hooks/pre-commit", "#!/bin/sh\necho mine\n")
    code, _, err = run("install-hook")
    assert code == 2 and "--force" in err
    assert hook.read_text() == "#!/bin/sh\necho mine\n"
    assert run("install-hook", "--force")[0] == 0
    assert "echo mine" not in hook.read_text()


def test_install_hook_append(repo, run):
    hook = write(repo, ".git/hooks/pre-commit", "#!/bin/sh\necho mine\n")
    assert run("install-hook", "--append")[0] == 0
    assert hook.read_text() == "#!/bin/sh\necho mine\nidlint scan --staged || exit $?\n"
    assert run("install-hook", "--append")[0] == 0  # idempotent
    assert hook.read_text().count("idlint scan --staged") == 1
    hook.write_text("#!/usr/bin/env python3\nprint('mine')\n")
    assert run("install-hook", "--append")[0] == 2  # not a shell script


def test_install_hook_uses_core_hookspath(repo, git, run):
    git("config", "core.hooksPath", ".githooks")
    assert run("install-hook")[0] == 0
    assert (repo / ".githooks" / "pre-commit").exists()


# --- end to end -------------------------------------------------------------------

def test_python_dash_m_entry_point(repo):
    write(repo, "a.txt", f"{PUBLIC_IP}\n")
    result = subprocess.run([sys.executable, "-m", "idlint", "scan"], cwd=repo, capture_output=True, text=True)
    assert result.returncode == 1 and "ipv4" in result.stdout


def test_installed_hook_blocks_commit_until_allowed(repo, git, run):
    assert run("install-hook")[0] == 0
    write(repo, "data.csv", f"score,host\n3,{PUBLIC_IP}\n")
    git("add", "data.csv")

    def commit():
        return subprocess.run(["git", "commit", "-m", "add data"], cwd=repo, capture_output=True, text=True)

    blocked = commit()
    assert blocked.returncode == 1
    assert "Commit blocked." in blocked.stdout + blocked.stderr
    assert PUBLIC_IP not in blocked.stdout + blocked.stderr
    assert git("status", "--porcelain").startswith("A  data.csv")

    assert run("allow", "data.csv:2", "--reason", "synthetic")[0] == 0
    allowed = commit()
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert "data.csv" in git("show", "--stat", "HEAD")


def test_repo_passes_its_own_scan(monkeypatch, run):
    monkeypatch.chdir(PROJECT_ROOT)
    code, out, _ = run("scan")
    assert code == 0, out


def test_hook_judges_what_commit_dash_a_would_commit(repo, git, run):
    write(repo, "notes.txt", "clean\n")
    git("add", ".")
    git("commit", "-qm", "init")
    assert run("install-hook")[0] == 0
    write(repo, "notes.txt", f"clean\n{PUBLIC_IP}\n")  # modified but never `git add`ed
    result = subprocess.run(["git", "commit", "-am", "edit"], cwd=repo, capture_output=True, text=True)
    assert result.returncode == 1
    assert "notes.txt" in result.stdout + result.stderr


def test_pre_commit_framework_manifest():
    text = (PROJECT_ROOT / ".pre-commit-hooks.yaml").read_text()
    for line in ("- id: idlint", "language: python", "entry: idlint scan --staged",
                 "pass_filenames: false", "always_run: true"):
        assert line in text
