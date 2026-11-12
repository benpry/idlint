# idlint: spec for a PII pre-commit scanner

Nov 11, 2026 · @Ben

## Summary

`idlint` is a command-line scanner that blocks a git commit when staged files contain text that looks like participant PII. It is aimed at research repos holding human-participant data: Prolific and MTurk IDs, IP addresses, coordinates, emails, and identifying column names.

Decisions already made:

- Python 3.11+, standard library only, so it installs anywhere with `pipx install` or by copying one package.
- Detection is regex plus a validator function per rule. No ML, no network calls.
- The hook scans the staged version of each file, not the working tree.
- Suppressions pin to a file, a rule and a hash of the line, so they survive line shifts and expire when the line changes.
- The tool never prints or stores a full matched value by default.

This spec is written to be handed to a coding agent. Where it says "must", treat it as an acceptance requirement.

## Prior art

No existing tool ships research-PII rules, but [gitleaks](https://github.com/gitleaks/gitleaks) already does the mechanics and is the fallback if this build stalls. It supports custom regex rules in TOML, a pre-commit hook, inline `gitleaks:allow` comments, and a `.gitleaksignore` file of `file:rule:line` fingerprints.

Reasons to build anyway:

- gitleaks fingerprints use the line number, so an ignore entry breaks whenever lines shift above it.
- Its regex engine has no validators, so it cannot range-check a latitude or reject a private IP.
- It has no notion of a CSV header, so it cannot flag a column named `first_name` whose values no regex would catch.
- It says nothing about binary data files (`.xlsx`, `.sav`, `.rds`) that cannot be scanned at all.

Small PII scanners on PyPI such as [pii-radar](https://pypi.org/project/pii-radar/0.3.1/) and [spanforge-secrets](https://pypi.org/project/spanforge-secrets/) cover email, phone, SSN, card and IP. None found covers Prolific IDs or coordinates. Both are young projects; their suppression features were not tested.

Borrow from gitleaks: the rule-ID naming style, the inline-comment convention, and the baseline idea.

## CLI

One executable, `idlint`, with these subcommands:

| Command | What it does |
| --- | --- |
| `idlint scan [PATHS...]` | Scan files or directories in the working tree. Default path is the repo root. Respects `.gitignore` unless `--no-gitignore`. |
| `idlint scan --staged` | Scan the staged content of files added or modified in the index. This is what the hook runs. |
| `idlint scan --tracked` | Scan every tracked file at `HEAD`. For a first audit of an existing repo. |
| `idlint allow FILE:LINE [--rule ID] [--reason TEXT]` | Add a suppression for the findings on that line. |
| `idlint allow --all [--reason TEXT]` | Suppress every current finding. Creates a baseline for an existing repo. |
| `idlint prune` | Remove suppressions that no longer match any line. |
| `idlint install-hook` | Write `.git/hooks/pre-commit`. Refuses to overwrite an existing hook unless `--force`; with `--append` it adds its line to an existing shell hook. |
| `idlint rules` | List rule IDs, severity, default on/off and a one-line description. |
| `idlint init` | Write a commented starter `.idlint.toml`. |

Flags on `scan`:

- `--format text|json|sarif` (default `text`).
- `--rules ID,ID` and `--skip-rules ID,ID` to override config for one run.
- `--show-values` to print matched text unmasked. Off by default.
- `--no-allowlist` to report everything, including suppressed findings.
- `--max-file-size BYTES` (default 5 MB; larger files produce an `oversize-file` warning, not a silent skip).

Exit codes: `0` no findings, `1` findings, `2` usage or runtime error. A scan error must never exit `0`.

## Detectors

Each rule is a compiled regex plus an optional Python validator that receives the match and its line and returns keep or drop. Rules run line by line. All patterns need word-boundary anchoring so they do not fire inside longer tokens.

### Value rules

| Rule ID | Matches | Validator | Default |
| --- | --- | --- | --- |
| `prolific-id` | Exactly 24 hex characters | Drop if part of a longer hex run. Drop if all one character. | on |
| `prolific-url-param` | `PROLIFIC_PID=`, `STUDY_ID=`, `SESSION_ID=` followed by a value | Drop if the value is a template placeholder such as `{{%PROLIFIC_PID%}}` or `${...}` | on |
| `mturk-worker-id` | `A` followed by 11 to 13 uppercase letters or digits | Require at least one digit and one letter after the `A` | on |
| `ipv4` | Dotted quad | Each octet 0 to 255. Drop loopback, private, link-local, `0.0.0.0`, broadcast and documentation ranges. Drop if the line looks like a version string (`version`, `==`, `>=`, `v` prefix). | on |
| `ipv6` | Full and `::`-compressed forms | Parse with `ipaddress`. Drop loopback, link-local, unique-local. | on |
| `lat-long-pair` | Two signed decimals separated by a comma, tab or whitespace, each with 4+ decimal places | First in \[-90, 90\], second in \[-180, 180\]. Also accept the swapped order. | on |
| `email` | Standard address pattern | Drop `example.com`, `example.org`, `test.com`, `noreply@`, and `git@` SSH remotes | on |
| `phone` | E.164 (`+` and 8 to 15 digits) and North American formats with separators | Drop if the digits sit inside a longer number | on |
| `us-ssn` | `NNN-NN-NNNN` | Drop area `000`, `666`, `9xx`; group `00`; serial `0000` | on |
| `credit-card` | 13 to 19 digits with optional spaces or dashes | Luhn check | on |
| `mac-address` | Six hex pairs with `:` or `-` | Drop all-zero and broadcast | on |
| `date-of-birth` | A date on a line that also contains `dob`, `birth` or `born` | Date parses | on |
| `us-zip` | 5 digits or ZIP+4 on a line containing `zip` or `postal` | None | off |
| `uuid` | Canonical UUID | None | off |

The Prolific and MTurk patterns are best-known formats, not published guarantees. The agent must make every pattern overridable in config, and the README must tell users to test the rules against a real export.

### Header rule

`sensitive-column` fires on the header row of `.csv`, `.tsv` and `.psv` files, and on JSON object keys, when a name matches a sensitive-name list. This catches fields regex cannot, such as names and free-text addresses. Matching is case-insensitive and ignores `_`, `-`, spaces and camelCase boundaries.

Default list: `prolific_pid`, `prolific_id`, `participant_id`, `worker_id`, `assignment_id`, `ip`, `ip_address`, `latitude`, `longitude`, `lat`, `lng`, `lon`, `location_latitude`, `location_longitude`, `email`, `recipient_email`, `first_name`, `last_name`, `recipient_first_name`, `recipient_last_name`, `full_name`, `phone`, `address`, `street`, `zip`, `postcode`, `dob`, `date_of_birth`, `ssn`, `user_agent`, `device_id`.

The list includes the identifying columns Qualtrics adds to exports (`IPAddress`, `LocationLatitude`, `LocationLongitude`, `RecipientEmail`, `RecipientFirstName`, `RecipientLastName`).

### File rules

- `unscannable-data-file`: any staged file with extension `.xlsx`, `.xls`, `.sav`, `.dta`, `.rds`, `.rdata`, `.parquet`, `.feather`, `.pkl`, `.pickle`, `.sqlite`, `.db`, `.h5`, `.mat`, `.zip`, `.gz`. The tool cannot read these, so it must flag them rather than pass them. Default on.
- `oversize-file`: text file above `--max-file-size`. Default on.
- Other binary files (detected by a NUL byte in the first 8 KB) are skipped silently.

### Volume control

A data file can produce thousands of hits. Text output must show at most 5 findings per rule per file, then a count of the rest. JSON and SARIF output list every finding.

## Allowlisting

Four mechanisms, checked in this order. A finding suppressed by any of them is not reported and does not affect the exit code.

### 1. Path excludes

Glob patterns in config, either global (`exclude_paths`) or per rule. Use for whole files such as `docs/*.md` or `tests/fixtures/**`.

### 2. Value allowlist

Literal strings or regexes in config, per rule, compared against the matched text. Use for a value that recurs everywhere, such as the lab server's IP or the team's contact email.

### 3. Inline comment

A line containing `idlint:allow` is skipped for all rules. `idlint:allow[ipv4,email]` skips only the named rules. Useful in code; not usable in CSV data, which is why mechanism 4 exists.

### 4. Line allowlist file

`.idlint-allow` at the repo root, committed, one entry per line:

```
# path : rule : line-hash : line-number-hint   # reason
data/pilot.csv:lat-long-pair:9f2c41d07a3e:17   # campus building coords, public
analysis/geo.py:ipv4:1b77e0c9a2f4:203          # example in docstring
```

Rules for this file:

- `line-hash` is the first 12 hex characters of SHA-256 over the line's content, with trailing whitespace and line ending stripped.
- An entry matches a finding when path, rule and line-hash all match. The line number is a hint for humans and is ignored for matching.
- If the line moves, the entry still matches. If the line's content changes, the entry stops matching and the finding returns. This is intended.
- Identical lines in one file are all covered by one entry.
- A rule of `*` covers every rule on that line.
- `idlint allow FILE:LINE` computes the hash and appends the entry. Users should not need to hash by hand.
- `idlint prune` deletes entries whose path is gone or whose hash matches no line. `scan` prints a one-line count of stale entries but does not fail on them.
- The file stores hashes, never the line text, so the allowlist cannot itself leak PII.
- File renames are not tracked. A renamed file needs new entries.

Caveat for the README: a truncated hash of a short, guessable line can be brute-forced. Only allowlist lines that have been judged not to be PII.

## Configuration

Optional `.idlint.toml` at the repo root, read with `tomllib`. With no config file, every default-on rule runs with default settings. Unknown keys must be an error (exit `2`), so a typo never silently disables a rule.

```toml
# Global
exclude_paths = ["docs/**", "*.lock", "renv/**"]
max_file_size = 5_000_000
extra_unscannable_extensions = [".jld2"]

# Turn built-in rules on or off
[rules]
us-zip = true
mac-address = false

# Tune a built-in rule
[rule.ipv4]
allow_values = ["128.112.0.10"]          # literal
allow_patterns = ['^10\.']                # regex on the match
exclude_paths = ["infra/**"]

[rule.prolific-id]
pattern = '\b[0-9a-f]{24}\b'              # override the default regex

[rule.sensitive-column]
add_names = ["sona_id", "netid"]
remove_names = ["address"]

# Define a new rule
[[custom_rule]]
id = "sona-id"
description = "SONA participant code"
pattern = '\bSONA-\d{5}\b'
require_on_line = ["sona"]               # optional keyword gate, case-insensitive
```

Precedence: command-line flags, then `.idlint.toml`, then built-in defaults. Custom rules get regex and keyword gating only; validators are for built-ins.

## Output

The scanner's own output must not become a leak, because hook output ends up in terminals, CI logs and pasted bug reports.

- Matched values are masked by default: first 2 and last 2 characters, the middle replaced with `*`, for example `5f**…**3a`. Values of 6 characters or fewer are fully masked.
- `--show-values` prints the raw match. JSON and SARIF follow the same flag.
- Nothing is written to disk except `.idlint-allow` and files the user asks for.

Text format, one finding per line, grouped by file:

```
data/raw/session1.csv
  1:4    sensitive-column   header "IPAddress"
  2:31   ipv4               73**…**12
  2:58   lat-long-pair      40**…**19
  ... 412 more ipv4, 412 more lat-long-pair
data/raw/responses.xlsx
  -      unscannable-data-file

3 rules fired in 2 files. Commit blocked.
Fix the data, or run: idlint allow FILE:LINE --reason "..."
```

JSON format is a list of objects with `path`, `line`, `column`, `rule`, `masked`, `line_hash`, and a top-level summary. Colors only when stdout is a TTY and `NO_COLOR` is unset.

## Git integration

`scan --staged` must read from the index, not the working tree, so a partially staged file is judged on what will actually be committed.

1. List files with `git diff --cached --name-only --diff-filter=ACMR -z`.
2. Read each with `git show :PATH` (bytes).
3. Scan the whole staged file, not only the added lines. A whole-file scan is simpler and catches data that was already present.
4. Read `.idlint.toml` and `.idlint-allow` from the working tree.

Hook installation, two supported routes:

- Native: `idlint install-hook` writes a POSIX shell script that runs `idlint scan --staged` and passes through the exit code. If `core.hooksPath` is set, install there.
- [pre-commit](https://pre-commit.com) framework: ship a `.pre-commit-hooks.yaml` with one hook, `id: idlint`, `language: python`, `entry: idlint scan --staged`, `pass_filenames: false`, `always_run: true`.

The README must state that `git commit --no-verify` bypasses the hook, and show a CI step running `idlint scan --tracked` as the backstop. It must also state that the tool checks new commits only; data already in history needs `git filter-repo` or similar.

## Implementation constraints

- Python 3.11+, no runtime dependencies. `pytest` is the only dev dependency.
- Packaged with `pyproject.toml`, console script `idlint`, also runnable as `python -m idlint`.
- Works on macOS, Linux and Windows. Normalize paths to forward slashes, relative to the repo root, everywhere they are stored or compared.
- Decode files as UTF-8 with `errors="replace"`; also handle a UTF-16 BOM, since Qualtrics exports can be UTF-16.
- Strip a trailing `\r` before hashing so CRLF and LF checkouts produce the same line hash.
- Parse `.idlint-allow` entries from the right, so a path containing `:` still parses.
- Lines longer than 10,000 characters are scanned in full but masked previews stay short. Avoid regexes with catastrophic backtracking; add a test with a 1 MB single-line file.
- Performance target: 50 MB of CSV across 100 files in under 10 seconds on a laptop.
- Jupyter notebooks are scanned as plain JSON text. No special handling in v1.

Suggested layout:

```
idlint/
  __main__.py      # entry point
  cli.py           # argparse, subcommands
  config.py        # load and validate .idlint.toml
  rules.py         # Rule dataclass, built-in rules, validators
  headers.py       # sensitive-column detection
  scanner.py       # file iteration, line scanning, findings
  gitio.py         # staged/tracked file listing and reading
  allowlist.py     # parse, match, add, prune
  report.py        # text, json, sarif; masking
tests/
.pre-commit-hooks.yaml
README.md
```

## Tests and acceptance criteria

All test fixtures must use synthetic values. The repo must pass its own scan, using its own allowlist for the fixtures.

Per rule, at least three true positives and three true negatives. Required negatives:

- `prolific-id`: a 40-character git SHA, a 32-character MD5, a 24-character run inside a longer hex string.
- `ipv4`: `192.168.1.1`, `127.0.0.1`, `numpy==1.26.4.0`, `256.1.1.1`.
- `lat-long-pair`: `(0.5, 0.25)`, `95.1234, 195.1234` (out of range in both orders), two p-values on one line with fewer than 4 decimals.
- `credit-card`: a 16-digit number failing Luhn.
- `email`: `git@github.com:org/repo.git`, `user@example.com`.

Behavior tests:

- [ ] `scan --staged` reports a finding that is staged but reverted in the working tree, and ignores one that is in the working tree but not staged.
- [ ] An allowlisted line still passes after 10 lines are inserted above it.
- [ ] An allowlisted line is reported again after one character of it changes.
- [ ] `idlint allow FILE:LINE` followed by `scan` exits `0`; `prune` removes the entry after the line is deleted.
- [ ] `idlint:allow[ipv4]` suppresses `ipv4` but not `email` on the same line.
- [ ] A CSV with header `Name,IPAddress,Score` yields `sensitive-column` for `IPAddress` only (`name` is not in the default list).
- [ ] A staged `.xlsx` yields `unscannable-data-file` and exit `1`.
- [ ] Default text output contains no full matched value; `--show-values` does.
- [ ] Unknown config key exits `2`.
- [ ] `install-hook` refuses to overwrite an existing hook without `--force`.
- [ ] End to end in a temp repo: the installed hook blocks `git commit` on a file with a public IP and allows it after `idlint allow`.
- [ ] CRLF and LF versions of the same file produce the same line hashes.

## Non-goals and open questions

Not in v1:

- Detecting personal names or free-text addresses in values. That needs NER; the header rule is the substitute.
- Reading inside binary formats. They are flagged, not parsed.
- Scanning git history, redacting files, or rewriting commits.
- Commit-message scanning.

Open questions for the owner:

- [ ] Should `name` be in the default sensitive-column list? It is left out because it often means a variable or condition name.
- [ ] Should `unscannable-data-file` block the commit or only warn?
- [ ] Is 24-hex the only Prolific ID shape in your exports? Check one real export before trusting the rule.
- [ ] Are there lab-specific IDs (SONA, university NetIDs, panel vendor IDs) to add as built-ins rather than custom rules?
- [ ] Is Python 3.11 available on every machine that will commit to these repos?
