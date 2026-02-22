"""File reading, literal replacement, and diff generation."""

import contextlib
import difflib
import logging
import os
import tempfile
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from trufflehog_redactor.parser import Finding

logger = logging.getLogger(__name__)


def generate_replacements(
    findings: List[Finding], placeholder: str
) -> Dict[str, Tuple[str, str]]:
    """For each file, produce (original_content, redacted_content).

    Secrets are replaced longest-first to avoid partial-match issues.
    """
    grouped = _group_by_file(findings)
    results: Dict[str, Tuple[str, str]] = {}

    for file_path, file_findings in grouped.items():
        if not _validate_file(file_path):
            continue

        try:
            with open(file_path, encoding="utf-8") as fh:
                original = fh.read()
        except (PermissionError, OSError) as exc:
            logger.warning(f"Cannot read {file_path}: {exc}")
            continue
        except UnicodeDecodeError as exc:
            logger.warning(f"Cannot decode {file_path} as UTF-8: {exc}")
            continue

        redacted = original
        # Sort by length descending so longer secrets are replaced first
        for f in sorted(file_findings, key=lambda x: len(x.secret), reverse=True):
            replacement = placeholder if placeholder else "*" * len(f.secret)
            redacted = redacted.replace(f.secret, replacement)

        if redacted != original:
            results[file_path] = (original, redacted)

    return results


def _group_by_file(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """Group findings by their file path."""
    grouped: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.file_path].append(f)
    return dict(grouped)


def _validate_file(file_path: str) -> bool:
    """Check that a file path is safe to read/write."""
    if os.path.islink(file_path):
        logger.warning(f"Skipping symlink: {file_path}")
        return False
    if not os.path.isfile(file_path):
        logger.warning(f"Skipping missing file: {file_path}")
        return False
    st = os.stat(file_path)
    if st.st_nlink > 1:
        logger.warning(
            f"{file_path} has {st.st_nlink} hard links — other links will "
            "retain the unredacted secret after redaction"
        )
    return True


def generate_diffs(
    replacements: Dict[str, Tuple[str, str]],
    findings: Optional[List[Finding]] = None,
) -> str:
    """Generate a unified diff string for all files.

    If *findings* is provided, secrets in the "before" lines are partially
    masked so the diff preview doesn't leak full secrets to the terminal.
    """
    diff_parts: List[str] = []

    if findings:
        from trufflehog_redactor.tui import mask_secret

    for file_path, (original, redacted) in sorted(replacements.items()):
        display_original = original
        display_redacted = redacted

        if findings:
            # Mask raw secrets in both sides so the diff doesn't leak them
            file_findings = sorted(
                [f for f in findings if f.file_path == file_path],
                key=lambda x: len(x.secret),
                reverse=True,
            )
            for f in file_findings:
                masked = mask_secret(f.secret)
                display_original = display_original.replace(f.secret, masked)
                display_redacted = display_redacted.replace(f.secret, masked)

        diff = difflib.unified_diff(
            display_original.splitlines(keepends=True),
            display_redacted.splitlines(keepends=True),
            fromfile=file_path,
            tofile=file_path,
        )
        diff_parts.append("".join(diff))

    return "\n".join(diff_parts)


def apply_redactions(replacements: Dict[str, Tuple[str, str]]) -> int:
    """Write redacted content to files atomically. Returns number of files modified."""
    count = 0
    for file_path, (_original, redacted) in replacements.items():
        dir_name = os.path.dirname(file_path) or "."
        try:
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(redacted)
                # Preserve original file permissions and ownership
                st = os.stat(file_path)
                os.chmod(tmp_path, st.st_mode)
                with contextlib.suppress(PermissionError):
                    os.chown(tmp_path, st.st_uid, st.st_gid)
                os.replace(tmp_path, file_path)
            except BaseException:
                # Clean up temp file on any failure
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
                raise
        except (PermissionError, OSError) as exc:
            logger.warning(f"Cannot write {file_path}: {exc}")
            continue
        count += 1
    return count
