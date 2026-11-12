import re
import tomllib

import pytest

from idlint import allowlist
from idlint.allowlist import AllowlistError, Entry

A = '"a.csv:ipv4:9f2c41d07a3e:7" = ""\n'


def test_line_hash_is_12_hex_and_ignores_line_ending_and_trailing_space():
    h = allowlist.line_hash("a,b,c")
    assert re.fullmatch(r"[0-9a-f]{12}", h)
    assert allowlist.line_hash("a,b,c\r") == h
    assert allowlist.line_hash("a,b,c  \t\r\n") == h
    assert allowlist.line_hash(" a,b,c") != h
    assert allowlist.line_hash("a,b,d") != h


def test_parse_entry():
    assert allowlist.parse_entry("data/pilot.csv:lat-long-pair:9f2c41d07a3e:17", "campus coords") == Entry(
        "data/pilot.csv", "lat-long-pair", "9f2c41d07a3e", 17, "campus coords")
    assert allowlist.parse_entry("plain.txt:*:000000000000:1") == Entry("plain.txt", "*", "000000000000", 1)


def test_parse_from_the_right_so_colons_in_paths_work():
    entry = allowlist.parse_entry("Study #2/run:1 final.csv:email:9f2c41d07a3e:4")
    assert (entry.path, entry.rule) == ("Study #2/run:1 final.csv", "email")


@pytest.mark.parametrize("bad", ["just some words", "a.csv:ipv4:nothex:3", "a.csv:ipv4:9f2c41d07a3e:x"])
def test_malformed_entry_is_an_error(bad):
    with pytest.raises(ValueError):
        allowlist.parse_entry(bad)


def test_from_table():
    assert allowlist.from_table({"a.csv:ipv4:9f2c41d07a3e:7": "why"}) == [
        Entry("a.csv", "ipv4", "9f2c41d07a3e", 7, "why")]
    for bad in ({"garbage": ""}, {"a.csv:ipv4:9f2c41d07a3e:7": 3}, ["a.csv:ipv4:9f2c41d07a3e:7"]):
        with pytest.raises(ValueError):
            allowlist.from_table(bad)


def test_format_entry_is_one_toml_line_that_round_trips():
    entry = Entry('Study #2/say "hi"\\run:1.csv', "ipv4", "9f2c41d07a3e", 7, 'see issue #12:\n"fine"')
    line = allowlist.format_entry(entry)
    assert "\n" not in line
    assert allowlist.from_table(tomllib.loads(line)) == [
        Entry(entry.path, "ipv4", "9f2c41d07a3e", 7, 'see issue #12: "fine"')]


def test_allows_matches_path_rule_and_hash_but_not_line_number():
    keys = allowlist.keys([Entry("a.csv", "ipv4", "9f2c41d07a3e", 7), Entry("b.csv", "*", "1b77e0c9a2f4", 1)])
    assert allowlist.allows(keys, "a.csv", "ipv4", "9f2c41d07a3e")
    assert not allowlist.allows(keys, "a.csv", "email", "9f2c41d07a3e")
    assert not allowlist.allows(keys, "other.csv", "ipv4", "9f2c41d07a3e")
    assert not allowlist.allows(keys, "a.csv", "ipv4", "000000000000")
    assert allowlist.allows(keys, "b.csv", "email", "1b77e0c9a2f4")


def test_stale():
    keep = Entry("a.csv", "ipv4", "9f2c41d07a3e", 7)
    gone_hash = Entry("a.csv", "ipv4", "1b77e0c9a2f4", 9)
    gone_path = Entry("deleted.csv", "ipv4", "9f2c41d07a3e", 1)
    live = {"a.csv": {"9f2c41d07a3e"}}
    assert allowlist.stale([keep, gone_hash, gone_path], lambda p: live.get(p, set())) == [gone_hash, gone_path]


def test_append_creates_the_table_and_skips_duplicates(tmp_path):
    path = tmp_path / ".idlint.toml"
    first = Entry("a.csv", "ipv4", "9f2c41d07a3e", 7, "why")
    assert allowlist.append(path, [first]) == 1
    again = Entry("a.csv", "ipv4", "9f2c41d07a3e", 99, "moved")
    second = Entry("a.csv", "email", "9f2c41d07a3e", 7)
    assert allowlist.append(path, [again, second, second]) == 1
    text = path.read_text()
    assert text.startswith("#") and text.count("[allow_lines]") == 1
    assert allowlist.from_table(tomllib.loads(text)["allow_lines"]) == [first, second]


def test_append_leaves_the_rest_of_the_config_alone(tmp_path):
    path = tmp_path / ".idlint.toml"
    original = '# my settings\nexclude_paths = ["docs/**"]  # keep\n\n[rules]\nemail = false'
    path.write_text(original)  # no trailing newline
    allowlist.append(path, [Entry("a.csv", "ipv4", "9f2c41d07a3e", 7)])
    text = path.read_text()
    assert text.startswith(original + "\n")
    data = tomllib.loads(text)
    assert data["exclude_paths"] == ["docs/**"] and data["rules"] == {"email": False}
    assert list(data["allow_lines"]) == ["a.csv:ipv4:9f2c41d07a3e:7"]


def test_append_inserts_into_a_table_that_is_not_last(tmp_path):
    path = tmp_path / ".idlint.toml"
    rest = '\n# tune ipv4\n[rule.ipv4]\nallow_values = ["x"]\n'
    path.write_text("[allow_lines]\n" + A + rest)
    allowlist.append(path, [Entry("b.csv", "email", "1b77e0c9a2f4", 2, "ok")])
    assert path.read_text() == "[allow_lines]\n" + A + '"b.csv:email:1b77e0c9a2f4:2" = "ok"\n' + rest


def test_prune_removes_stale_entries_and_keeps_everything_else(tmp_path):
    path = tmp_path / ".idlint.toml"
    before = 'exclude_paths = ["docs/**"]\n\n[allow_lines]\n# reviewed by the lab\n' + A
    after = "\n[rules]\nemail = false\n"
    path.write_text(before + '"a.csv:ipv4:1b77e0c9a2f4:9" = "gone"\n"deleted.csv:ipv4:9f2c41d07a3e:1" = ""\n' + after)
    live = {"a.csv": {"9f2c41d07a3e"}}
    assert allowlist.prune(path, lambda p: live.get(p, set())) == 2
    assert path.read_text() == before + after


def test_prune_with_nothing_to_do_does_not_touch_the_file(tmp_path):
    path = tmp_path / ".idlint.toml"
    assert allowlist.prune(path, lambda p: set()) == 0
    assert not path.exists()
    path.write_text("[allow_lines]\r\n" + A)
    assert allowlist.prune(path, lambda p: {"9f2c41d07a3e"}) == 0
    assert path.read_bytes() == ("[allow_lines]\r\n" + A).encode()


def test_an_edit_that_cannot_be_made_safely_is_refused(tmp_path):
    path = tmp_path / ".idlint.toml"
    original = 'allow_lines = { "a.csv:ipv4:9f2c41d07a3e:7" = "" }\n'  # inline form the editor does not handle
    path.write_text(original)
    with pytest.raises(AllowlistError, match="by hand"):
        allowlist.append(path, [Entry("b.csv", "email", "1b77e0c9a2f4", 2)])
    with pytest.raises(AllowlistError, match="by hand"):
        allowlist.prune(path, lambda p: set())
    assert path.read_text() == original
