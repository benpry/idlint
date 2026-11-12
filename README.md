# idlint

`idlint` blocks a git commit when the staged files contain text that looks like participant PII. It is built for research repos that hold human-participant data: Prolific and MTurk IDs, IP addresses, coordinates, emails, and identifying column names.

It is a pre-commit check, not a guarantee:

- **`git commit --no-verify` bypasses the hook.** Run `idlint scan --tracked` in CI as the backstop (see [CI](#ci)).
- **It checks new commits only.** Data that is already in history stays there until you rewrite it with `git filter-repo` or a similar tool.
- **The Prolific and MTurk patterns are best-known formats, not published guarantees.** Test the rules against one of your own real exports before trusting them (see [Check the rules against a real export](#check-the-rules-against-a-real-export)).

## Install

Python 3.11 or newer, no dependencies.

```
pipx install git+https://github.com/benpry/idlint
```

The `idlint/` package is standard library only, so copying it into a repo and running `python -m idlint` also works.

## Quick start

```
cd your-repo
idlint scan --tracked      # first audit of what is already committed
idlint allow --all --reason "baseline, reviewed 2026-11"   # optional: accept what is there now
idlint install-hook        # block new PII from here on
```

When a commit is blocked you see something like this:

```
data/raw/session1.csv
  1:4    sensitive-column   header "IPAddress"
  2:31   ipv4               73**…**12
  2:58   lat-long-pair      40**…**19
  ... 412 more ipv4, 412 more lat-long-pair
data/raw/responses.xlsx
  -      unscannable-data-file

827 findings: 4 rules fired in 2 files. Commit blocked.
Fix the data, or run: idlint allow FILE:LINE --reason "..."
```

Either remove the data from the commit, or tell idlint the line is fine with `idlint allow`.

## Commands

| Command | What it does |
| --- | --- |
| `idlint scan [PATHS...]` | Scan files or directories in the working tree. Default is the repo root. Directories respect `.gitignore` unless `--no-gitignore`; a file you name explicitly is always scanned. |
| `idlint scan --staged` | Scan the staged content of files added or modified in the index. This is what the hook runs. |
| `idlint scan --tracked` | Scan every tracked file at `HEAD`. |
| `idlint allow FILE:LINE [--rule ID] [--reason TEXT]` | Add a suppression for the findings on that line to `.idlint.toml`. `--rule '*'` covers every rule on the line. |
| `idlint allow FILE [--reason TEXT]` | Add a suppression for a whole-file finding (`unscannable-data-file`, `oversize-file`). |
| `idlint allow --all [--reason TEXT]` | Suppress every current finding in the working tree. Creates a baseline for an existing repo. |
| `idlint prune` | Remove `[allow_lines]` entries that no longer match any line. |
| `idlint install-hook` | Write the `pre-commit` hook. Refuses to overwrite an existing hook unless `--force`; `--append` adds its line to an existing shell hook. |
| `idlint rules` | List rule IDs, severity, default on/off and a description. |
| `idlint init` | Write a commented starter `.idlint.toml`. |

Flags on `scan`:

- `--format text|json|sarif` (default `text`).
- `--rules ID,ID` runs only those rules; `--skip-rules ID,ID` turns rules off. Both override the config for one run.
- `--show-values` prints matched text unmasked.
- `--no-allowlist` reports everything, ignoring all four suppression mechanisms.
- `--max-file-size BYTES` (default 5,000,000).

Exit codes: `0` no findings, `1` findings, `2` usage or runtime error. Every finding sets exit code `1`, whatever its severity.

Outside a git repository, `idlint scan` treats the current directory as the root.

## Rules

Each value rule is a regex plus a validator that drops look-alikes. Rules run line by line.

| Rule ID | Matches | Dropped by the validator | Default |
| --- | --- | --- | --- |
| `prolific-id` | Exactly 24 hex characters | Part of a longer hex run; all one character | on |
| `prolific-url-param` | `PROLIFIC_PID=`, `STUDY_ID=`, `SESSION_ID=` followed by a value | Template placeholders such as `{{%PROLIFIC_PID%}}` or `${...}`: the value must start with a letter or digit | on |
| `mturk-worker-id` | `A` followed by 11 to 13 uppercase letters or digits | No digit, or no letter, after the `A` | on |
| `ipv4` | Dotted quad | Octet above 255; loopback, private, link-local, `0.x.x.x`, documentation ranges, multicast and reserved (`224.0.0.0` and up, which includes broadcast and netmasks); version numbers | on |
| `ipv6` | Full and `::`-compressed forms | Unparseable; unspecified, loopback, link-local, unique-local | on |
| `lat-long-pair` | Two signed decimals with 4+ decimal places, separated by a comma, tab or spaces (optionally quoted) | Out of range for latitude/longitude in both orders | on |
| `email` | Standard address pattern | `example.com`, `example.org`, `test.com`, `noreply@`, `git@` SSH remotes | on |
| `phone` | E.164 (`+` and 8 to 15 digits) and North American formats with separators | Digits inside a longer number | on |
| `us-ssn` | `NNN-NN-NNNN` | Area `000`, `666`, `9xx`; group `00`; serial `0000` | on |
| `credit-card` | 13 to 19 digits, contiguous or grouped 4-4-4-N or 4-6-5 with spaces or dashes | Fails the Luhn check; first digit outside 2 to 6 | on |
| `mac-address` | Six hex pairs with `:` or `-` | All-zero and broadcast | on |
| `date-of-birth` | A date on a line that also contains `dob`, `birth` or `born` | Dates that do not parse | on |
| `us-zip` | 5 digits or ZIP+4 on a line containing `zip` or `postal` | | off |
| `uuid` | Canonical UUID | | off |

Notes on choices that are narrower than the obvious reading:

- `ipv4` treats a dotted quad as a version number only when the marker sits directly before it: `version = "1.2.3.4"`, `numpy==1.26.4.0`, `v2.10.3.1`, or a product token such as `Chrome/120.0.0.0`. The word "version" elsewhere on a data row does not hide an address on that row.
- `credit-card` does not accept arbitrary spacing between digits, and drops numbers that do not start with 2 to 6. This keeps space-separated digit columns and 13-digit millisecond timestamps from firing.
- `lat-long-pair` fires on any two adjacent in-range decimals with four or more decimal places, including model coefficients. Exclude those files or disable the rule where that is a problem.

### sensitive-column

Fires on the header row of `.csv`, `.tsv` and `.psv` files, and on object keys in `.json`, `.jsonl` and `.ndjson` files, when a name is on the sensitive-name list. This catches fields no regex can, such as names and free-text addresses. Matching is case-insensitive and ignores `_`, `-`, spaces and camelCase boundaries, so `IPAddress`, `ip_address` and `IP Address` are the same name.

Default list: `prolific_pid`, `prolific_id`, `participant_id`, `worker_id`, `assignment_id`, `ip`, `ip_address`, `latitude`, `longitude`, `lat`, `lng`, `lon`, `location_latitude`, `location_longitude`, `email`, `recipient_email`, `first_name`, `last_name`, `recipient_first_name`, `recipient_last_name`, `full_name`, `phone`, `address`, `street`, `zip`, `postcode`, `dob`, `date_of_birth`, `ssn`, `user_agent`, `device_id`.

That covers the identifying columns Qualtrics adds to exports. `name` is not on the list because it often means a variable or condition name; add it with `add_names` if you want it.

### File rules

- `unscannable-data-file`: any file with extension `.xlsx`, `.xls`, `.sav`, `.dta`, `.rds`, `.rdata`, `.parquet`, `.feather`, `.pkl`, `.pickle`, `.sqlite`, `.db`, `.h5`, `.mat`, `.zip`, `.gz`. idlint cannot read these, so it flags them rather than passing them.
- `oversize-file`: a text file above the size limit. It is reported and not scanned. If you turn this rule off, oversize files are skipped without a message.
- Other binary files (a NUL byte in the first 8 KB) are skipped silently.

Jupyter notebooks are scanned as plain text.

### Check the rules against a real export

Before relying on idlint, run it on one real export from each platform you use and confirm the IDs are caught. Name the file explicitly, so it is scanned even if it is gitignored, and keep it out of the commit:

```
idlint scan path/to/real_export.csv
idlint scan path/to/real_export.csv --show-values   # only in a private terminal
```

If an ID format is missed, override the pattern or add a custom rule in `.idlint.toml`.

## Allowlisting

Four mechanisms. A finding suppressed by any of them is not reported and does not affect the exit code.

1. **Path excludes.** Glob patterns in config, global (`exclude_paths`) or per rule. Use for whole files such as `docs/*.md` or `tests/fixtures/**`. `*` and `?` stay within one directory, `**` crosses directories, and a pattern without `/` matches a file name at any depth. Character classes (`[abc]`) are not supported.
2. **Value allowlist.** Literal strings (`allow_values`) or regexes (`allow_patterns`) in config, per rule, compared against the matched text. Use for a value that recurs everywhere, such as the lab server's IP.
3. **Inline comment.** A line containing `idlint:allow` is skipped for all rules; `idlint:allow[ipv4,email]` skips only the named rules. Useful in code, not usable in CSV data.
4. **Line allowlist.** The `[allow_lines]` table of `.idlint.toml`, one entry per line:

```toml
# "path:rule:line-hash:line-number-hint" = "reason"
[allow_lines]
"data/pilot.csv:lat-long-pair:9f2c41d07a3e:17" = "campus building coords, public"
"analysis/geo.py:ipv4:1b77e0c9a2f4:203" = "example in docstring"
```

How the table behaves:

- `line-hash` is the first 12 hex characters of SHA-256 over the line's content, without trailing whitespace or the line ending. CRLF and LF checkouts hash the same.
- An entry matches when path, rule and hash all match. The line number is a hint for people and is ignored.
- If the line moves, the entry still matches. If the line's content changes, the entry stops matching and the finding comes back. This is intended.
- Identical lines in one file are all covered by one entry.
- A rule of `*` covers every rule on that line.
- Whole-file findings use a hash of the file's bytes and line `0`, so the entry expires when the file changes.
- `idlint allow` computes hashes for you. `idlint prune` deletes entries whose file is gone or whose hash matches nothing in it. `scan` prints a count of stale entries but does not fail on them.
- Renames are not tracked. A renamed file needs new entries.
- `idlint allow` and `idlint prune` edit only the lines of this table. The rest of `.idlint.toml`, including comments, is left as it is, and `idlint allow` creates the file or the table if it is missing. If the table is written in a form they cannot edit line by line (an inline table, for example), they change nothing and print what to add or remove by hand.
- The hook reads `.idlint.toml` from the working tree, so new entries take effect before they are committed.

The table stores hashes, never line text, so it cannot leak PII by itself. **Caveat:** a truncated hash of a short, guessable line can be brute-forced. Only allowlist lines you have judged not to be PII.

## Configuration

All configuration, including the line allowlist, lives in one optional file: `.idlint.toml` at the repo root. `idlint init` writes a commented starter. With no config file, every default-on rule runs with default settings. An unknown key is an error (exit `2`), so a typo never silently disables a rule.

```toml
# Global
exclude_paths = ["docs/**", "*.lock", "renv/**"]
max_file_size = 5_000_000
extra_unscannable_extensions = [".jld2"]

# Turn built-in rules on or off
[rules]
us-zip = true
mac-address = false

# Tune a rule
[rule.ipv4]
allow_values = ["198.51.100.20"]         # literal
allow_patterns = ['^198\.51\.']           # regex searched in the match
exclude_paths = ["infra/**"]

[rule.prolific-id]
pattern = '\b[0-9a-f]{24}\b'              # override the default regex; the validator still runs

[rule.sensitive-column]
add_names = ["sona_id", "netid"]
remove_names = ["address"]

# Define a new rule
[[custom_rule]]
id = "sona-id"
description = "SONA participant code"
pattern = '\bSONA-\d{5}\b'
require_on_line = ["sona"]               # optional keyword gate, case-insensitive

# Lines judged not to be PII, written by `idlint allow` (see Allowlisting)
[allow_lines]
"data/pilot.csv:lat-long-pair:9f2c41d07a3e:17" = "campus building coords, public"
```

Precedence: command-line flags, then `.idlint.toml`, then built-in defaults. Every value rule's `pattern` can be overridden. If a pattern has a named group `value`, that group is what gets reported and compared against the value allowlist. Custom rules get a regex and a keyword gate only.

## Output

The scanner's own output must not become a leak, because hook output ends up in terminals, CI logs and pasted bug reports.

- Matched values are masked by default: the first 2 and last 2 characters with the middle replaced, for example `5f**…**3a`. Values of 6 characters or fewer are fully masked. Header and key names are shown as they are.
- `--show-values` prints the raw match. In JSON it adds a `value` field; in SARIF it puts the value in the message.
- Text output shows at most 5 findings per rule per file, then a count of the rest. JSON and SARIF list every finding.
- JSON is `{"findings": [...], "summary": {...}}`; each finding has `path`, `line`, `column`, `rule`, `masked` and `line_hash`.
- Colors appear only when stdout is a terminal and `NO_COLOR` is unset.
- Nothing is written to disk except `.idlint.toml` (by `allow`, `prune` and `init`) and the hook (by `install-hook`).

## Git integration

`scan --staged` reads from the index, not the working tree, so a partially staged file is judged on what will be committed. It scans the whole staged file, not only the added lines.

For a full session, from a blocked commit to one that goes through, see [examples/git-hook.md](examples/git-hook.md).

Native hook:

```
idlint install-hook
```

This writes a POSIX shell script that runs `idlint scan --staged` and passes its exit code through. If `core.hooksPath` is set, the hook is installed there. `idlint` must be on `PATH` when git runs the hook; if it is not, the commit fails rather than passing unchecked. With `--append`, the line goes at the end of the existing hook, so it will not run if that hook exits earlier.

[pre-commit](https://pre-commit.com) framework:

```yaml
repos:
  - repo: https://github.com/benpry/idlint
    rev: v0.1.0   # a tag or commit
    hooks:
      - id: idlint
```

### CI

`git commit --no-verify` skips every pre-commit hook, and a collaborator may never have installed it. Run the full scan in CI as the backstop:

```yaml
# .github/workflows/idlint.yml
name: idlint
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install git+https://github.com/benpry/idlint
      - run: idlint scan --tracked
```

By the time CI fails, the data has already been pushed. idlint checks new commits only; removing data from history needs `git filter-repo` or similar, and anything pushed to a shared remote should be treated as disclosed.

## Not in this version

- Detecting personal names or free-text addresses in values. That needs NER; `sensitive-column` is the substitute.
- Reading inside binary formats. They are flagged, not parsed.
- Scanning git history, redacting files, or rewriting commits.
- Commit-message scanning.

## Development

```
uv sync
uv run pytest            # fast suite
uv run pytest -m slow    # performance test: 50 MB of CSV across 100 files in under 10 s
```

All test fixtures are synthetic. The repo passes its own scan; the fixture lines are listed in the `[allow_lines]` table of `.idlint.toml`. After editing a line that holds a synthetic value, run `idlint prune` and `idlint allow FILE:LINE` (or `idlint allow --all`) again.
