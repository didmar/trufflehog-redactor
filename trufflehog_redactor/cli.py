"""CLI orchestration: parse args, read findings, launch TUI, apply redactions."""

import argparse
import io
import subprocess
import sys

from trufflehog_redactor.parser import parse_findings
from trufflehog_redactor.redactor import (
    apply_redactions,
    generate_diffs,
    generate_replacements,
)
from trufflehog_redactor.tui import run_tui


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="trufflehog-redactor",
        description="Interactively redact secrets found by TruffleHog.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to scan with trufflehog (used when input is not piped)",
    )
    parser.add_argument(
        "--placeholder",
        default="",
        help="Replacement string for secrets "
        "(default: asterisks matching secret length)",
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="Skip diff preview and confirmation prompt",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying files",
    )
    args = parser.parse_args()

    if args.path:
        stream = _run_trufflehog(args.path)
    elif not sys.stdin.isatty():
        stream = sys.stdin
    else:
        parser.error(
            "No piped input detected and no path provided.\n"
            "Usage: trufflehog-redactor /path/to/scan\n"
            "   or: trufflehog filesystem /path/to/scan --json --no-update --no-fail"
            " 2>/dev/null | trufflehog-redactor"
        )

    findings = parse_findings(stream)

    if not findings:
        print("No secrets found in input.")
        return

    print(f"Found {len(findings)} unique secret(s) across files.\n")

    selected = findings if args.no_confirm else run_tui(findings)

    if not selected:
        print("No secrets selected. Nothing to do.")
        return

    replacements = generate_replacements(selected, args.placeholder)

    if not replacements:
        print("No matching secrets found in files. Nothing to do.")
        return

    diff_output = generate_diffs(replacements, findings=selected)

    if not args.no_confirm and not _confirm_changes(len(replacements), diff_output):
        print("Aborted.")
        return

    if args.dry_run:
        if args.no_confirm:
            print(diff_output)
        print(f"Dry run: {len(replacements)} file(s) would be modified.")
        return

    count = apply_redactions(replacements)
    print(f"Redacted secrets in {count} file(s).")


def _confirm_changes(num_files: int, diff_output: str) -> bool:
    """Show diff preview, prompt via /dev/tty. Returns True if user confirms."""
    print("\n--- Diff preview ---\n")
    print(diff_output)
    print("--- End preview ---\n")

    try:
        with open("/dev/tty") as tty:
            prompt = f"Apply changes to {num_files} file(s)? [y/N] "
            print(prompt, end="", flush=True)
            answer = tty.readline().strip().lower()
    except OSError:
        print(
            "Cannot read confirmation (no TTY). Use --no-confirm.",
            file=sys.stderr,
        )
        sys.exit(1)

    return answer == "y"


def _run_trufflehog(path: str) -> io.StringIO:
    """Run trufflehog on *path* and return its JSON output as a stream."""
    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", path, "--json", "--no-update", "--no-fail"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print(
            "Error: 'trufflehog' is not installed or not on your PATH.\n"
            "Install it from https://github.com/trufflesecurity/trufflehog",
            file=sys.stderr,
        )
        sys.exit(1)

    if result.returncode not in (0, 1):
        # trufflehog exits 1 when it finds secrets; other codes are errors
        print("trufflehog exited with an error:", file=sys.stderr)
        sys.stderr.write(result.stderr)
        sys.exit(result.returncode)

    return io.StringIO(result.stdout)
