import time

import pytest
from samples import EMAIL, OTHER_IP, PUBLIC_IP

from idlint import allowlist, config, scanner

DEFAULT = config.parse("")


def scan(path, text, cfg=DEFAULT, **kwargs):
    data = text if isinstance(text, bytes) else text.encode()
    return scanner.scan_file(path, data, cfg, **kwargs)


def summary(findings):
    return [(f.line, f.column, f.rule) for f in findings]


def test_reports_line_column_rule_and_hash_in_position_order():
    text = f"id,contact\n7,{EMAIL} from {PUBLIC_IP}\n8,{OTHER_IP}\n"
    findings = scan("notes.txt", text)
    assert summary(findings) == [(2, 3, "email"), (2, 32, "ipv4"), (3, 3, "ipv4")]
    assert findings[0].value == EMAIL
    assert findings[0].line_hash == allowlist.line_hash(f"7,{EMAIL} from {PUBLIC_IP}")
    assert findings[0].path == "notes.txt"


def test_inline_allow_all_rules():
    assert scan("a.py", f'HOST = "{PUBLIC_IP}"  # idlint:allow\n') == []


def test_inline_allow_named_rules_only():
    line = f'x = "{PUBLIC_IP} {EMAIL}"  # idlint:allow[ipv4]\n'
    assert summary(scan("a.py", line)) == [(1, 17, "email")]
    both = f'x = "{PUBLIC_IP} {EMAIL}"  # idlint:allow[ipv4, email]\n'
    assert scan("a.py", both) == []


def test_value_allowlist():
    cfg = config.parse(f'[rule.ipv4]\nallow_values = ["{PUBLIC_IP}"]\nallow_patterns = [\'^151\\.\']')
    assert scan("a.txt", f"{PUBLIC_IP}\n{OTHER_IP}\n", cfg) == []
    assert summary(scan("a.txt", "8.8.4.4\n", cfg)) == [(1, 1, "ipv4")]


def test_path_excludes_global_and_per_rule():
    cfg = config.parse('exclude_paths = ["docs/**"]\n[rule.ipv4]\nexclude_paths = ["infra/**"]')
    text = f"{PUBLIC_IP} {EMAIL}\n"
    assert scan("docs/a.md", text, cfg) == []
    assert summary(scan("infra/hosts", text, cfg)) == [(1, 12, "email")]
    assert len(scan("src/a.txt", text, cfg)) == 2


def test_suppress_false_reports_everything():
    cfg = config.parse(f'exclude_paths = ["docs/**"]\n[rule.ipv4]\nallow_values = ["{PUBLIC_IP}"]')
    text = f"{PUBLIC_IP}  # idlint:allow\n{OTHER_IP}  # idlint:allow[ipv4]\n"
    assert scan("docs/a.md", text, cfg) == []
    assert summary(scan("docs/a.md", text, cfg, suppress=False)) == [(1, 1, "ipv4"), (2, 1, "ipv4")]


def test_disabled_and_default_off_rules_do_not_fire():
    assert scan("a.txt", "zip: 08544\n") == []
    assert summary(scan("a.txt", "zip: 08544\n", DEFAULT.select(only=["us-zip"]))) == [(1, 6, "us-zip")]
    assert scan("a.txt", f"{PUBLIC_IP}\n", DEFAULT.select(skip=["ipv4"])) == []


def test_unscannable_data_file_is_flagged_not_passed():
    data = b"PK\x03\x04 not really a workbook"
    (finding,) = scan("data/Responses.XLSX", data)
    assert (finding.rule, finding.line, finding.value) == ("unscannable-data-file", 0, "")
    assert finding.line_hash == allowlist.content_hash(data)
    cfg = config.parse('extra_unscannable_extensions = [".jld2"]')
    assert [f.rule for f in scan("x.jld2", b"abc", cfg)] == ["unscannable-data-file"]
    assert scan("data/r.xlsx", data, DEFAULT.select(skip=["unscannable-data-file"])) == []


def test_other_binary_files_are_skipped_silently():
    assert scan("logo.png", b"\x89PNG\x00\x00" + PUBLIC_IP.encode()) == []


def test_oversize_text_file_is_flagged_and_not_scanned():
    cfg = config.parse("max_file_size = 20")
    data = f"{PUBLIC_IP}\n{OTHER_IP}\n".encode()
    (finding,) = scan("big.csv", data, cfg)
    assert (finding.rule, finding.line) == ("oversize-file", 0)
    assert finding.line_hash == allowlist.content_hash(data)


def test_csv_header_yields_sensitive_column_for_listed_names_only():
    findings = scan("data/s1.csv", "Name,IPAddress,Score\nx,y,3\n")
    assert summary(findings) == [(1, 6, "sensitive-column")]
    assert findings[0].label == 'header "IPAddress"'
    assert scan("notes.txt", "Name,IPAddress,Score\n") == []  # not a delimited data file


def test_header_names_can_be_added_and_removed():
    cfg = config.parse('[rule.sensitive-column]\nadd_names = ["netid"]\nremove_names = ["ip_address"]')
    assert [f.label for f in scan("d.tsv", "NetID\tIPAddress\n", cfg)] == ['header "NetID"']


def test_json_keys_yield_sensitive_column():
    findings = scan("d.json", '{\n  "trial": 1,\n  "email": null\n}\n')
    assert summary(findings) == [(3, 4, "sensitive-column")]
    assert findings[0].label == 'key "email"'


def test_utf16_and_utf8_bom_files_are_decoded():
    text = f"IPAddress,Score\n{PUBLIC_IP},3\n"
    expected = [(1, 1, "sensitive-column"), (2, 1, "ipv4")]
    assert summary(scan("q.csv", text.encode("utf-16"))) == expected
    assert summary(scan("q.csv", b"\xef\xbb\xbf" + text.encode())) == expected


def test_invalid_utf8_does_not_crash():
    assert summary(scan("a.txt", b"caf\xe9 " + PUBLIC_IP.encode() + b"\n")) == [(1, 6, "ipv4")]


def test_crlf_and_lf_versions_have_the_same_line_hashes():
    lf = f"a,b\n1,{PUBLIC_IP}\n2,{EMAIL}\n"
    crlf = lf.replace("\n", "\r\n")
    assert [f.line_hash for f in scan("a.txt", lf)] == [f.line_hash for f in scan("a.txt", crlf)]
    assert scanner.file_hashes(lf.encode()) - scanner.file_hashes(crlf.encode()) == {
        allowlist.content_hash(lf.encode())}


def test_file_hashes_cover_every_line_and_the_whole_file():
    data = b"one\ntwo\n"
    assert scanner.file_hashes(data) >= {
        allowlist.line_hash("one"), allowlist.line_hash("two"), allowlist.content_hash(data)}
    binary = b"\x00\x01"
    assert scanner.file_hashes(binary) == {allowlist.content_hash(binary)}


@pytest.mark.parametrize("unit", [
    "a", "1", "f0", "1.", "a.", "a@", "@a.", "1 ", "0-", "12:", "::", "9.1234,", "+1", "(555) ", "A1", '"a":', "Jan ",
])
def test_one_megabyte_single_line_does_not_backtrack_catastrophically(unit):
    line = unit * (1_000_000 // len(unit))
    cfg = DEFAULT.select(only=[r for r in DEFAULT.rules if r != "oversize-file"])
    start = time.perf_counter()
    scan("big.json", line, cfg)
    scan("big.csv", line + f",{EMAIL}", cfg)
    assert time.perf_counter() - start < 5
