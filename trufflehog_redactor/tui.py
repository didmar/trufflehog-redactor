"""Curses-based TUI for selecting which findings to redact."""

import curses
import os
import sys
from typing import List

from trufflehog_redactor.parser import Finding

# Layout constants
_HEADER_ROWS = 3  # Rows occupied by title + controls + separator
_BOTTOM_RESERVE = 1  # Rows reserved at the bottom for the status bar
_DETECTOR_COL_WIDTH = 16  # Fixed column width for detector name
_MIN_SECRET_WIDTH = 10  # Minimum display width for the masked secret
_MIN_PATH_WIDTH = 5  # Minimum display width for the file path
_PATH_BUDGET = 20  # Space reserved for path when computing secret width
_ELLIPSIS = "..."  # Truncation indicator


def mask_secret(secret: str, visible: int = 4) -> str:
    """Show first and last `visible` chars, mask the middle."""
    if len(secret) <= visible * 2:
        return "*" * len(secret)
    return secret[:visible] + "*" * (len(secret) - visible * 2) + secret[-visible:]


def run_tui(findings: List[Finding]) -> List[Finding]:
    """Launch curses TUI and return the list of selected findings."""
    if not findings:
        return []

    tty_file = _open_tty()
    if tty_file is None:
        return []

    selected = [True] * len(findings)
    cursor = 0
    top = 0
    reveal = False

    def draw(stdscr: "curses.window") -> List[Finding]:
        nonlocal cursor, top, reveal
        curses.curs_set(0)
        curses.use_default_colors()

        while True:
            stdscr.clear()
            max_y, max_x = stdscr.getmaxyx()
            list_start = _HEADER_ROWS
            visible = max_y - list_start - _BOTTOM_RESERVE

            top_val = _adjust_scroll(cursor, top, visible)
            # Update the outer `top` so it persists across iterations
            top = top_val

            _draw_header(stdscr, max_x)
            _draw_list(stdscr, findings, selected, cursor, top, reveal, max_y, max_x)
            stdscr.refresh()

            key = stdscr.getch()
            cursor, reveal, result = _handle_key(
                key,
                findings,
                selected,
                cursor,
                reveal,
            )
            if result is not None:
                return result

    old_stdin_fd = os.dup(0)
    os.dup2(tty_file.fileno(), 0)
    try:
        os.environ.setdefault("TERM", "xterm-256color")
        result = curses.wrapper(draw)
    finally:
        os.dup2(old_stdin_fd, 0)
        os.close(old_stdin_fd)
        tty_file.close()

    return result


def _open_tty():
    """Open /dev/tty for curses I/O, returning the file object or None on failure."""
    try:
        tty_fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        print(
            "Error: No TTY available for interactive selection.\n"
            "Hint: use --no-confirm to skip interactive mode.",
            file=sys.stderr,
        )
        return None

    try:
        return os.fdopen(tty_fd, "r+b", buffering=0)
    except OSError:
        os.close(tty_fd)
        print("Error: Could not open TTY file descriptor.", file=sys.stderr)
        return None


def _adjust_scroll(cursor: int, top: int, visible: int) -> int:
    """Return an updated scroll offset so the cursor stays visible."""
    if cursor < top:
        return cursor
    if cursor >= top + visible:
        return cursor - visible + 1
    return top


def _draw_header(stdscr: "curses.window", max_x: int) -> None:
    """Draw the title bar, controls hint, and separator line."""
    header = "trufflehog-redactor: Select secrets to redact"
    controls = (
        "↑/↓:move  space:toggle  a:all  t:category  r:reveal  enter:confirm  q:quit"
    )
    stdscr.addnstr(0, 0, header, max_x - 1, curses.A_BOLD)
    stdscr.addnstr(1, 0, controls, max_x - 1, curses.A_DIM)
    stdscr.addnstr(2, 0, "─" * (max_x - 1), max_x - 1)


def _draw_list(
    stdscr: "curses.window",
    findings: List[Finding],
    selected: List[bool],
    cursor: int,
    top: int,
    reveal: bool,
    max_y: int,
    max_x: int,
) -> None:
    """Draw the scrollable list of findings and the status bar."""
    list_start = _HEADER_ROWS
    visible = max_y - list_start - _BOTTOM_RESERVE

    for idx in range(top, min(top + visible, len(findings))):
        row = list_start + idx - top
        _draw_finding_row(
            stdscr,
            row,
            max_x,
            findings[idx],
            selected[idx],
            idx == cursor,
            reveal,
        )

    count = sum(selected)
    status = f"{count}/{len(findings)} selected"
    stdscr.addnstr(max_y - 1, 0, status, max_x - 1, curses.A_DIM)


def _draw_finding_row(
    stdscr: "curses.window",
    row: int,
    max_x: int,
    finding: Finding,
    is_selected: bool,
    is_cursor: bool,
    reveal: bool,
) -> None:
    """Render a single finding row at the given screen position."""
    mark = "x" if is_selected else " "
    masked = finding.secret if reveal else mask_secret(finding.secret)
    prefix = f"[{mark}] {finding.detector_name:<{_DETECTOR_COL_WIDTH}s} "
    secret_max = max(_MIN_SECRET_WIDTH, max_x - 1 - len(prefix) - 1 - _PATH_BUDGET)
    masked = _truncate_secret(masked, secret_max)
    path_max = max(_MIN_PATH_WIDTH, max_x - 1 - len(prefix) - len(masked) - 1)
    path_display = _truncate_path(finding.file_path, path_max)
    line = f"{prefix}{masked} {path_display}"
    attr = curses.A_REVERSE if is_cursor else 0
    stdscr.addnstr(row, 0, line, max_x - 1, attr)


def _truncate_secret(text: str, max_width: int) -> str:
    """Truncate a masked secret to max_width, adding ellipsis at the end."""
    if len(text) <= max_width:
        return text
    if max_width <= len(_ELLIPSIS):
        return text[:max_width]
    return text[: max_width - len(_ELLIPSIS)] + _ELLIPSIS


def _truncate_path(path: str, max_width: int) -> str:
    """Truncate a file path to max_width, adding ellipsis in the middle."""
    if len(path) <= max_width:
        return path
    if max_width <= len(_ELLIPSIS):
        return path[:max_width]
    side = (max_width - len(_ELLIPSIS)) // 2
    return path[:side] + _ELLIPSIS + path[-(max_width - len(_ELLIPSIS) - side) :]


def _handle_key(
    key: int,
    findings: List[Finding],
    selected: List[bool],
    cursor: int,
    reveal: bool,
) -> tuple:
    """Process a keypress and return (cursor, reveal, result).

    *result* is None while the loop should continue, a list of Finding
    when the user confirms, or an empty list when they quit.
    """
    if key == curses.KEY_UP or key == ord("k"):
        cursor = max(0, cursor - 1)
    elif key == curses.KEY_DOWN or key == ord("j"):
        cursor = min(len(findings) - 1, cursor + 1)
    elif key == ord(" "):
        selected[cursor] = not selected[cursor]
    elif key == ord("a"):
        if all(selected):
            selected[:] = [False] * len(findings)
        else:
            selected[:] = [True] * len(findings)
    elif key == ord("t"):
        cat = findings[cursor].detector_name
        indices = [i for i, f in enumerate(findings) if f.detector_name == cat]
        if all(selected[i] for i in indices):
            for i in indices:
                selected[i] = False
        else:
            for i in indices:
                selected[i] = True
    elif key == ord("r"):
        reveal = not reveal
    elif key == ord("\n"):
        return cursor, reveal, [f for f, s in zip(findings, selected) if s]
    elif key == ord("q"):
        return cursor, reveal, []

    return cursor, reveal, None
