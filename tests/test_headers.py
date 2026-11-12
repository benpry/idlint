import pytest

from idlint.headers import DEFAULT_NAMES, header_hits, json_key_hits, normalize

NAMES = frozenset(normalize(n) for n in DEFAULT_NAMES)


def test_csv_header_flags_only_listed_names():
    assert header_hits("Name,IPAddress,Score", ",", NAMES) == [(6, "IPAddress")]


@pytest.mark.parametrize("name", [
    "IPAddress", "LocationLatitude", "LocationLongitude",
    "RecipientEmail", "RecipientFirstName", "RecipientLastName",
    "first-name", "Date Of Birth", "PROLIFIC_PID", "userAgent",
])
def test_name_matching_ignores_case_and_separators(name):
    assert normalize(name) in NAMES


@pytest.mark.parametrize("name", ["name", "condition", "email_opt_in", "zipped", "response"])
def test_unlisted_names_do_not_match(name):
    assert normalize(name) not in NAMES


def test_tsv_psv_and_quoted_headers():
    assert header_hits("trial\temail\trt", "\t", NAMES) == [(7, "email")]
    assert header_hits("trial|worker_id", "|", NAMES) == [(7, "worker_id")]
    assert header_hits('"trial, n","Email"', ",", NAMES) == [(13, "Email")]


def test_json_keys():
    line = '{"trial": 1, "email": "x", "nested": {"IPAddress" : "y"}}'
    assert json_key_hits(line, NAMES) == [(15, "email"), (40, "IPAddress")]
    assert json_key_hits('["email", "phone"]', NAMES) == []  # values, not keys


def test_oversized_header_field_is_not_an_error():
    assert header_hits("x" * 200_000 + ",email", ",", NAMES) == []
