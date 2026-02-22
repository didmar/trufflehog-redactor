An interactive terminal tool that scans your files for secrets with [TruffleHog](https://github.com/trufflesecurity/trufflehog) and helps you redact them.

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

# Features

- **One-command scanning** — runs TruffleHog for you, no piping required
- **Interactive TUI** — curses-based selector to pick which secrets to redact
- **Diff preview** — review a unified diff of all changes before applying
- **Safe by default** — shows what will change and asks for confirmation
- **Zero dependencies** — only uses the Python standard library
- **Custom placeholders** — replace secrets with `[REDACTED]`, asterisks, or any string

# Installation

Note: Works on **macOS** and **Linux**. Windows is not currently supported (the interactive TUI depends on `curses` and Unix terminal features).

Requires [TruffleHog](https://github.com/trufflesecurity/trufflehog#installation) to be installed and available on your `PATH`.

Install from PyPI:

```bash
pip install trufflehog-redactor
```

Or run directly without installing:

```bash
uvx trufflehog-redactor ./my-project
```

Or install via pipx:

```bash
pipx install trufflehog-redactor
```

# Usage

Point `trufflehog-redactor` at the directory you want to scan:

```bash
trufflehog-redactor ./my-project
```

This will:

1. Run TruffleHog to detect secrets in the target directory
2. Open an interactive TUI to select which secrets to redact
3. Show a diff preview of the proposed changes
4. Apply the redactions after confirmation

## Examples

Scan the current directory interactively:

```bash
trufflehog-redactor .
```

Redact all secrets without prompting:

```bash
trufflehog-redactor . --no-confirm
```

Preview changes without modifying files:

```bash
trufflehog-redactor . --dry-run
```

Use a custom placeholder:

```bash
trufflehog-redactor . --placeholder "[REDACTED]"
```

## Pipe mode

You can also pipe TruffleHog JSON output directly if you need more control over TruffleHog flags:

```bash
trufflehog filesystem ./my-project --no-fail --no-update --json 2>/dev/null | trufflehog-redactor
```

This can be useful to run trufflehog via Docker, without installing it locally. 

## TUI Controls

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `Space` | Toggle selection |
| `a` | Toggle all |
| `t` | Toggle by detector category |
| `r` | Reveal / hide secrets |
| `Enter` | Confirm selection |
| `q` | Quit without redacting |

# Testing with example secrets

The [test_keys](https://github.com/trufflesecurity/test_keys) repo from TruffleSecurity contains real-looking example secrets you can use to try out the tool end-to-end:

```bash
# Clone the test repo
git clone https://github.com/trufflesecurity/test_keys /tmp/test_keys

trufflehog-redactor /tmp/test_keys
```

> **Tip:** Start with `--dry-run` to preview changes safely before applying any redactions.

# License

[MIT](LICENSE)
