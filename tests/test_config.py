import pytest

from idlint import config
from idlint.allowlist import Entry
from idlint.config import ConfigError
from idlint.rules import BUILTIN_RULES

SPEC_EXAMPLE = r"""
exclude_paths = ["docs/**", "*.lock", "renv/**"]
max_file_size = 5_000_000
extra_unscannable_extensions = [".jld2"]

[rules]
us-zip = true
mac-address = false

[rule.ipv4]
allow_values = ["128.112.0.10"]
allow_patterns = ['^10\.']
exclude_paths = ["infra/**"]

[rule.prolific-id]
pattern = '\b[0-9a-f]{24}\b'

[rule.sensitive-column]
add_names = ["sona_id", "netid"]
remove_names = ["address"]

[[custom_rule]]
id = "sona-id"
description = "SONA participant code"
pattern = '\bSONA-\d{5}\b'
require_on_line = ["sona"]
"""


def test_defaults_without_a_config_file(tmp_path):
    cfg = config.load(tmp_path)
    assert cfg.enabled == {r.id for r in BUILTIN_RULES.values() if r.default_on}
    assert cfg.max_file_size == 5_000_000
    assert {".xlsx", ".sav", ".rds", ".parquet", ".gz"} <= cfg.unscannable_extensions
    assert not cfg.path_excluded("docs/a.md")


def test_spec_example_parses():
    cfg = config.parse(SPEC_EXAMPLE)
    assert "us-zip" in cfg.enabled and "mac-address" not in cfg.enabled
    assert "sona-id" in cfg.enabled and cfg.rules["sona-id"].require_on_line == ("sona",)
    assert ".jld2" in cfg.unscannable_extensions
    assert cfg.value_allowed("ipv4", "128.112.0.10")
    assert cfg.value_allowed("ipv4", "10.1.2.3")
    assert not cfg.value_allowed("ipv4", "73.54.12.9")
    assert not cfg.value_allowed("email", "128.112.0.10")
    assert cfg.path_excluded("infra/hosts.txt", "ipv4")
    assert not cfg.path_excluded("infra/hosts.txt", "email")
    assert cfg.path_excluded("docs/deep/a.md", "email")
    assert "sonaid" in cfg.sensitive_names and "netid" in cfg.sensitive_names
    assert "address" not in cfg.sensitive_names and "ipaddress" in cfg.sensitive_names


def test_pattern_override_keeps_the_validator():
    cfg = config.parse(SPEC_EXAMPLE)
    rule = cfg.rules["prolific-id"]
    assert rule.pattern.pattern == r"\b[0-9a-f]{24}\b"
    assert rule.find("id 5f3c2a1b9d8e7f6a5b4c3d2e ok")
    assert not rule.find("id 000000000000000000000000 ok")  # validator still applies


def test_custom_rule_keyword_gate():
    cfg = config.parse("""
[[custom_rule]]
id = "panel-code"
pattern = 'P-[0-9]{5}'
require_on_line = ["Panel"]
""")
    rule = cfg.rules["panel-code"]
    assert rule.find("PANEL member P-12345")
    assert not rule.find("part number P-12345")


@pytest.mark.parametrize("text", [
    "exclude_path = ['docs/**']",  # typo in a top-level key
    "[rules]\nipv5 = false",  # unknown rule id
    "[rules]\nipv4 = 'off'",  # not a boolean
    "[rule.ipv4]\nallow_value = ['1.2.3.4']",  # typo in a rule key
    "[rule.nope]\nallow_values = ['x']",  # unknown rule id
    "[rule.sensitive-column]\npattern = 'x'",  # header rule has no pattern
    "[rule.ipv4]\nadd_names = ['x']",  # only for sensitive-column
    "[rule.ipv4]\npattern = '('",  # bad regex
    "[rule.ipv4]\nallow_patterns = ['(']",
    "[rule.ipv4]\nallow_values = '1.2.3.4'",  # not a list
    "max_file_size = 'big'",
    "[[custom_rule]]\nid = 'x'",  # missing pattern
    "[[custom_rule]]\nid = 'x'\npattern = 'y'\ncolour = 'red'",
    "[[custom_rule]]\nid = 'ipv4'\npattern = 'y'",  # clashes with a built-in
    "[[custom_rule]]\nid = 'my rule'\npattern = 'y'",  # ids must be safe in allow_lines keys and --rules
    "[[custom_rule]]\nid = 'a:b'\npattern = 'y'",
    "[[custom_rule]]\nid = '*'\npattern = 'y'",
    "this is not toml",
    '[allow_lines]\n"garbage" = ""',  # not path:rule:line-hash:line
    '[allow_lines]\n"a.csv:ipv4:9f2c41d07a3e:7" = 3',  # reason must be a string
    "allow_lines = ['a.csv:ipv4:9f2c41d07a3e:7']",  # must be a table
])
def test_invalid_config_is_an_error(text):
    with pytest.raises(ConfigError):
        config.parse(text)


@pytest.mark.parametrize("path,pattern,expected", [
    ("docs/a.md", "docs/**", True),
    ("docs/x/y/a.md", "docs/**", True),
    ("mydocs/a.md", "docs/**", False),
    ("uv.lock", "*.lock", True),
    ("sub/dir/poetry.lock", "*.lock", True),
    ("docs/a.md", "docs/*.md", True),
    ("docs/sub/a.md", "docs/*.md", False),
    ("a/b/secret.csv", "**/secret.csv", True),
    ("secret.csv", "**/secret.csv", True),
    ("tests/fixtures/x/y.csv", "tests/fixtures/**", True),
    ("data/run1.csv", "data/run?.csv", True),
    ("data/run10.csv", "data/run?.csv", False),
])
def test_path_globs(path, pattern, expected):
    assert config.path_matches(path, pattern) is expected


def test_select_overrides_enabled_rules_for_one_run():
    cfg = config.parse("")
    assert cfg.select(only=["us-zip", "ipv4"]).enabled == {"us-zip", "ipv4"}
    assert "email" not in cfg.select(skip=["email"]).enabled
    with pytest.raises(ConfigError):
        cfg.select(only=["nope"])
    with pytest.raises(ConfigError):
        cfg.select(skip=["nope"])


def test_load_reads_idlint_toml(tmp_path):
    (tmp_path / ".idlint.toml").write_text("[rules]\nemail = false\n")
    assert "email" not in config.load(tmp_path).enabled
    (tmp_path / ".idlint.toml").write_text("oops = 1\n")
    with pytest.raises(ConfigError, match="oops"):
        config.load(tmp_path)


def test_allow_lines_table():
    cfg = config.parse(
        '[allow_lines]\n"data/pilot.csv:lat-long-pair:9f2c41d07a3e:17" = "campus building coords, public"\n')
    assert cfg.allow_lines == (
        Entry("data/pilot.csv", "lat-long-pair", "9f2c41d07a3e", 17, "campus building coords, public"),)
    assert config.parse("").allow_lines == ()
