# Example: idlint as a git pre-commit hook

A walkthrough of one study repo, from installing the hook to getting a commit through. The output shown is what idlint prints, apart from the shortened repo path. All values are synthetic.

## The repo

Two new files are about to be committed. One is a pilot export that still has the participants' IP addresses in it. The other is an analysis config that names the lab's server.

```
$ cat data/pilot.csv
ResponseId,IPAddress,Duration,Score
R_1a2b,73.54.12.9,412,7
R_3c4d,151.101.1.69,388,5

$ cat analysis/config.py
LAB_SERVER = "128.112.0.10"
N_TRIALS = 40
```

## 1. Install the hook

Run this once per clone. Hooks are not copied by `git clone`, so every collaborator has to do it.

```
$ idlint install-hook
Installed pre-commit hook at /path/to/study/.git/hooks/pre-commit

$ cat .git/hooks/pre-commit
#!/bin/sh
# Installed by `idlint install-hook`.
exec idlint scan --staged
```

From now on git runs `idlint scan --staged` before every commit and cancels the commit if it exits non-zero.

## 2. A commit is blocked

```
$ git add data analysis
$ git commit -m "Add pilot data"
analysis/config.py
  1:15   ipv4               12**…**10
data/pilot.csv
  1:12   sensitive-column   header "IPAddress"
  2:8    ipv4               73**…**.9
  3:8    ipv4               15**…**69

4 findings: 2 rules fired in 2 files. Commit blocked.
Fix the data, or run: idlint allow FILE:LINE --reason "..."
```

Nothing was committed. Each finding gives `line:column`, the rule, and the match with its middle masked, so this output is safe to paste into an issue.

There are two different situations here, and they get different fixes.

## 3. Real PII: fix the data

The IP column in `data/pilot.csv` is participant data and should not be in the repo. Drop it:

```
$ cut -d, -f1,3,4 data/pilot.csv > tmp && mv tmp data/pilot.csv
$ git commit -m "Add pilot data"
analysis/config.py
  1:15   ipv4               12**…**10
data/pilot.csv
  1:12   sensitive-column   header "IPAddress"
  2:8    ipv4               73**…**.9
  3:8    ipv4               15**…**69

4 findings: 2 rules fired in 2 files. Commit blocked.
```

Still blocked, with the same findings. The hook judges the staged copy, which is what the commit would contain, and the fix has not been staged yet. Stage it:

```
$ git add data/pilot.csv
$ git commit -m "Add pilot data"
analysis/config.py
  1:15   ipv4   12**…**10

1 finding: 1 rule fired in 1 file. Commit blocked.
```

The CSV is clean now.

## 4. Not PII: allow the line

The remaining finding is the lab server's address, which is public and belongs in the config. Tell idlint, with a reason:

```
$ idlint allow analysis/config.py:1 --reason "lab server address, already public"
Added 1 entry to .idlint.toml

$ cat .idlint.toml
# Lines judged not to be PII. `idlint allow` adds entries and `idlint prune` removes stale ones.
# "path:rule:line-hash:line-number-hint" = "reason"
[allow_lines]
"analysis/config.py:ipv4:2e1e21fea00c:1" = "lab server address, already public"
```

The entry stores a hash of the line, not the line. Commit `.idlint.toml` along with the rest so collaborators and CI get the same decision:

```
$ git add .idlint.toml
$ git commit -m "Add pilot data"
[main (root-commit) 16a4b7b] Add pilot data
 3 files changed, 9 insertions(+)
 create mode 100644 .idlint.toml
 create mode 100644 analysis/config.py
 create mode 100644 data/pilot.csv
```

If the same address appears in many files, a value allowlist is less work than one entry per line:

```toml
[rule.ipv4]
allow_values = ["128.112.0.10"]
```

## 5. Later edits

The allowed line can move without being flagged again, and anything new is still checked. Here the server line moves from line 1 to line 2 and a new address is added:

```
$ cat analysis/config.py
N_TRIALS = 40
LAB_SERVER = "128.112.0.10"
BACKUP = "73.54.12.9"

$ git commit -am "Add backup server"
analysis/config.py
  3:11   ipv4   73**…**.9

1 finding: 1 rule fired in 1 file. Commit blocked.
Fix the data, or run: idlint allow FILE:LINE --reason "..."
```

Only line 3 is reported. If the text of the allowed line itself changes, its entry stops matching and the finding comes back; `idlint prune` then removes the dead entry.

## If the repo already has a pre-commit hook

`install-hook` will not overwrite it. Use `--append` to add idlint to the end of a shell hook:

```
$ idlint install-hook
idlint: error: /path/to/study/.git/hooks/pre-commit already exists; use --append to add idlint to it or --force to replace it

$ idlint install-hook --append
Installed pre-commit hook at /path/to/study/.git/hooks/pre-commit

$ cat .git/hooks/pre-commit
#!/bin/sh
ruff check .
idlint scan --staged || exit $?
```

The line goes last, so it does not run if the existing hook exits before reaching it.

## What the hook does not cover

- `git commit --no-verify` skips it, and so does a clone where nobody ran `idlint install-hook`. Run `idlint scan --tracked` in CI as the backstop; the README has a workflow.
- It checks new commits only. Data already in history needs `git filter-repo` or similar.
