import json

from samples import EMAIL, PUBLIC_IP

from idlint import report
from idlint.rules import BUILTIN_RULES
from idlint.scanner import Finding


def finding(path="data/s1.csv", line=2, column=31, rule="ipv4", value=PUBLIC_IP, label=""):
    return Finding(path, line, column, rule, value, "9f2c41d07a3e", label)


def test_mask_keeps_two_characters_at_each_end():
    assert report.mask(PUBLIC_IP) == "73**…**.9"
    assert report.mask("1234567") == "12**…**67"
    assert report.mask("123456") == "******"
    assert report.mask("ab") == "**"
    assert len(report.mask("x" * 50_000)) == 9


def test_text_groups_by_file_and_masks_values():
    findings = [
        finding(line=1, column=4, rule="sensitive-column", value="IPAddress", label='header "IPAddress"'),
        finding(),
        finding(path="data/r.xlsx", line=0, column=0, rule="unscannable-data-file", value=""),
    ]
    text = report.render_text(findings, staged=True)
    lines = text.splitlines()
    assert lines[0] == "data/s1.csv"
    assert lines[1].split() == ["1:4", "sensitive-column", "header", '"IPAddress"']
    assert lines[2].split() == ["2:31", "ipv4", "73**…**.9"]
    assert lines[3] == "data/r.xlsx"
    assert lines[4].split() == ["-", "unscannable-data-file"]
    assert "3 findings: 3 rules fired in 2 files. Commit blocked." in text
    assert "idlint allow FILE:LINE" in text
    assert PUBLIC_IP not in text
    assert "\x1b[" not in text


def test_text_show_values_prints_the_raw_match():
    assert PUBLIC_IP in report.render_text([finding()], show_values=True)
    assert "Commit blocked" not in report.render_text([finding()])


def test_text_shows_at_most_five_findings_per_rule_per_file():
    findings = [finding(line=n, value=f"73.54.12.{n}") for n in range(1, 9)]
    findings += [finding(line=n, rule="email", value=EMAIL) for n in range(1, 13)]
    findings += [finding(path="z.csv", line=1)]
    text = report.render_text(sorted(findings, key=lambda f: (f.path, f.line)))
    section = text.split("z.csv")[0]
    assert section.count(" ipv4 ") == 5 and section.count(" email ") == 5
    assert "  ... 3 more ipv4, 7 more email" in section
    assert "..." not in text.split("z.csv")[1].split("\n\n")[0]


def test_text_when_clean_and_stale_count():
    assert report.render_text([], files_scanned=3) == "No findings in 3 files.\n"
    assert report.render_text([], staged=True) == ""
    assert "2 stale entries in .idlint.toml" in report.render_text([], staged=True, stale=2)


def test_text_color_only_when_asked():
    assert "\x1b[" in report.render_text([finding()], color=True)


def test_json_lists_every_finding_with_summary():
    findings = [finding(line=n) for n in range(1, 9)] + [finding(path="r.xlsx", line=0, column=0,
                                                                 rule="oversize-file", value="")]
    data = json.loads(report.render_json(findings, files_scanned=4, stale=1))
    assert len(data["findings"]) == 9
    assert data["findings"][0] == {
        "path": "data/s1.csv", "line": 1, "column": 31, "rule": "ipv4",
        "masked": "73**…**.9", "line_hash": "9f2c41d07a3e",
    }
    assert data["summary"] == {
        "findings": 9, "files": 2, "files_scanned": 4,
        "rules": {"ipv4": 8, "oversize-file": 1}, "stale_allow_entries": 1,
    }
    assert PUBLIC_IP not in report.render_json(findings)
    shown = json.loads(report.render_json(findings, show_values=True))
    assert shown["findings"][0]["value"] == PUBLIC_IP


def test_sarif_is_valid_2_1_0_shape():
    findings = [finding(), finding(path="r.xlsx", line=0, column=0, rule="unscannable-data-file", value="")]
    text = report.render_sarif(findings, BUILTIN_RULES)
    data = json.loads(text)
    assert data["version"] == "2.1.0"
    (run,) = data["runs"]
    assert run["tool"]["driver"]["name"] == "idlint"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"ipv4", "unscannable-data-file"}
    first, second = run["results"]
    assert first["ruleId"] == "ipv4" and first["level"] == "error"
    location = first["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "data/s1.csv"
    assert location["region"] == {"startLine": 2, "startColumn": 31}
    assert "region" not in second["locations"][0]["physicalLocation"]
    assert second["level"] == "warning"
    assert PUBLIC_IP not in text
    assert PUBLIC_IP in report.render_sarif(findings, BUILTIN_RULES, show_values=True)


def test_text_columns_stay_separated_for_long_positions():
    rows = report.render_text([finding(line=123456, column=7890)]).splitlines()
    assert rows[1].split() == ["123456:7890", "ipv4", "73**…**.9"]
