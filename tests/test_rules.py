"""True positives and true negatives for every value rule. All values are synthetic."""

import pytest

from idlint.rules import BUILTIN_RULES

POSITIVES = {
    "prolific-id": [
        "5f3c2a1b9d8e7f6a5b4c3d2e",
        "pid=60a1b2c3d4e5f60718293a4b,done",
        "sub_5e8f9a0b1c2d3e4f5a6b7c8d.csv",
    ],
    "prolific-url-param": [
        "https://study.example.org/?PROLIFIC_PID=5f3c2a1b9d8e7f6a5b4c3d2e",
        "&STUDY_ID=60a1b2c3d4e5f60718293a4b&x=1",
        "SESSION_ID=0a1b2c3d4e5f",
    ],
    "mturk-worker-id": [
        "A1B2C3D4E5F6G7",
        "worker A3HJ8KLMN0PQ,approved",
        "A2XYZ9QRSTUVW",
    ],
    "ipv4": [
        "73.54.12.9",
        "ip=151.101.1.69,",
        '"172.32.0.1"',
        "8.8.4.4 connected",
        "http://73.54.12.9/path",
        "version: 2, ip: 73.54.12.9",  # a version elsewhere on the line does not hide an address
    ],
    "ipv6": [
        "2607:f8b0:4005:805::200e",
        "2a03:2880:f12f:83:face:b00c:0:25de",
        "addr=2001:4860:4860::8888;",
    ],
    "lat-long-pair": [
        "40.3573, -74.6672",
        "40.35730\t-74.66720",
        "-33.8688 151.2093",
        '"51.50735","-0.12776"',
        "151.2093, -33.8688",  # swapped order: longitude first
    ],
    "email": [
        "jane.doe@university.edu",
        "p.smith+study@mail.co.uk",
        "contact: a_b@lab-site.org,",
    ],
    "phone": [
        "+14155550123",
        "(609) 555-0142",
        "609-555-0142",
        "1-609-555-0142",
        "609.555.0142",
        "+442079460958",
    ],
    "us-ssn": [
        "123-45-6789",
        "ssn: 078-05-1120",
        '"219-09-9999"',
    ],
    "credit-card": [
        "4111111111111111",
        "4111 1111 1111 1111",
        "5500-0000-0000-0004",
        "3782 822463 10005",
    ],
    "mac-address": [
        "00:1A:2B:3C:4D:5E",
        "a4-83-e7-12-9f-0c",
        "mac=3c:22:fb:45:6a:01;",
    ],
    "date-of-birth": [
        "dob: 1990-05-17",
        "Date of birth: 05/17/1990",
        "born 17 May 1990",
        '"birthdate": "March 3, 1985"',
    ],
    "us-zip": [
        "zip: 08544",
        "postal code 94103-1234",
        "ZIP,08540",
    ],
    "uuid": [
        "123e4567-e89b-42d3-a456-426614174000",
        "id=9B2C1F0E-7A6D-4C3B-8E2F-0A1B2C3D4E5F,",
        '"0f8fad5b-d9cb-469f-a165-70867728950e"',
    ],
}

NEGATIVES = {
    "prolific-id": [
        "f8160b5d9b1e47af7ea038dff1339694d4e3ea26",  # 40-char git SHA
        "d41d8cd98f00b204e9800998ecf8427e",  # 32-char MD5
        "x5f3c2a1b9d8e7f6a5b4c3d2e99",  # 24 hex inside a longer hex run
        "000000000000000000000000",  # all one character
        "5f3c2a1b9d8e7f6a5b4c3d2",  # 23 characters
    ],
    "prolific-url-param": [
        "?PROLIFIC_PID={{%PROLIFIC_PID%}}&STUDY_ID={{%STUDY_ID%}}",
        "PROLIFIC_PID=${e://Field/PROLIFIC_PID}",
        "PROLIFIC_PID=%7B%7B%25PROLIFIC_PID%25%7D%7D",
        "MY_SESSION_ID=0a1b2c3d4e5f",
        "STUDY_ID=&next=1",
        "`PROLIFIC_PID=`, `STUDY_ID=` followed by a value",  # prose, not a value
    ],
    "mturk-worker-id": [
        "ABCDEFGHIJKLMN",  # no digit
        "A12345678901",  # no letter after the A
        "A1B2C3D4E5F6G7H8I9",  # too long
        "XA1B2C3D4E5F6G7",  # inside a longer token
    ],
    "ipv4": [
        "192.168.1.1",
        "127.0.0.1",
        "numpy==1.26.4.0",
        "256.1.1.1",
        "10.0.0.5",
        "169.254.1.1",
        "0.0.0.0",
        "255.255.255.255",
        "192.0.2.44",
        "198.51.100.7",
        "203.0.113.9",
        'version = "4.18.2.1"',
        "release v2.10.3.1",
        "pandas>=2.1.0.1",
        "1.2.3.4.5",
        "Mozilla/5.0 (X11) Chrome/120.0.0.0 Safari/537.36",  # product version in a user agent
    ],
    "ipv6": [
        "::1",
        "fe80::1ff:fe23:4567:890a",
        "fd12:3456:789a:1::1",
        "12:34:56",
        "x :: y",
        "00:1a:2b:3c:4d:5e",
    ],
    "lat-long-pair": [
        "(0.5, 0.25)",
        "95.1234, 195.1234",  # out of range in both orders
        "p = 0.031, 0.047",  # fewer than 4 decimals
        "123.4567, 150.1234",
        "0.12345",
    ],
    "email": [
        "git@github.com:org/repo.git",
        "user@example.com",
        "someone@example.org",
        "someone@test.com",
        "noreply@university.edu",
        "@decorator",
        "user@localhost",
    ],
    "phone": [
        "6095550142",  # no separators
        "1609-555-01421",  # inside a longer number
        "+1234567",  # too short for E.164
        "2026-03-15",
    ],
    "us-ssn": [
        "000-12-3456",
        "666-12-3456",
        "900-12-3456",
        "123-00-4567",
        "123-45-0000",
        "1234-56-7890",
    ],
    "credit-card": [
        "4111111111111112",  # 16 digits failing Luhn
        "1700000000000",  # millisecond timestamp
        "41111111111111111111",  # 20 digits
        "2026-03-15 2026-03-16",
    ],
    "mac-address": [
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
        "00:1A:2B:3C:4D",
        "00:1A:2B:3C:4D:5E:6F",
    ],
    "date-of-birth": [
        "created: 1990-05-17",  # no keyword
        "dob: 1990-13-45",  # does not parse
        "dob: 31/31/1990",
        "birth year unknown",
    ],
    "us-zip": [
        "count: 08544",  # no keyword
        "zip: 1234",
        "zip: 123456",
    ],
    "uuid": [
        "123e4567-e89b-42d3-a456",
        "123e4567-e89b-42d3-a456-42661417400g",
        "123e4567-e89b-42d3-a456-4266141740001",
    ],
}


def cases(table):
    return [(rule, line) for rule, lines in table.items() for line in lines]


def found(rule_id, line):
    return [m.group(0) for m in BUILTIN_RULES[rule_id].find(line)]


@pytest.mark.parametrize("rule_id,line", cases(POSITIVES))
def test_true_positive(rule_id, line):
    assert found(rule_id, line), f"{rule_id} should fire on {line!r}"


@pytest.mark.parametrize("rule_id,line", cases(NEGATIVES))
def test_true_negative(rule_id, line):
    assert not found(rule_id, line), f"{rule_id} should not fire on {line!r}"


def test_every_value_rule_has_three_positives_and_negatives():
    value_rules = {r.id for r in BUILTIN_RULES.values() if r.pattern is not None}
    assert value_rules == set(POSITIVES) == set(NEGATIVES)
    for rule_id in value_rules:
        assert len(POSITIVES[rule_id]) >= 3
        assert len(NEGATIVES[rule_id]) >= 3


def test_default_on_and_off():
    off = {r.id for r in BUILTIN_RULES.values() if not r.default_on}
    assert off == {"us-zip", "uuid"}
    assert {"sensitive-column", "unscannable-data-file", "oversize-file"} <= set(BUILTIN_RULES)


def test_url_param_reports_only_the_value():
    rule = BUILTIN_RULES["prolific-url-param"]
    (m,) = rule.find("?PROLIFIC_PID=5f3c2a1b9d8e7f6a5b4c3d2e&x=1")
    assert rule.value(m) == "5f3c2a1b9d8e7f6a5b4c3d2e"


def test_match_does_not_fire_inside_longer_token():
    assert not found("us-ssn", "id9123-45-6789")
    assert not found("email", "")
    assert found("ipv4", "a 73.54.12.9, b") == ["73.54.12.9"]
