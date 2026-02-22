"""Tests for trufflehog_redactor.tui (pure-function tests only)."""

import curses

import pytest

from trufflehog_redactor.parser import Finding
from trufflehog_redactor.tui import (
    _adjust_scroll,
    _handle_key,
    _truncate_path,
    _truncate_secret,
    mask_secret,
)

# -- mask_secret --------------------------------------------------------------


@pytest.mark.parametrize(
    "desc, secret, visible, expected",
    [
        ("long", "ABCDEFGHIJKLMNOP", 4, "ABCD********MNOP"),
        ("boundary-equal", "ABCDEFGH", 4, "********"),
        ("short", "ABCDE", 4, "*****"),
        ("single-char", "A", 4, "*"),
        ("custom-visible", "ABCDEFGHIJKLMNOP", 2, "AB************OP"),
    ],
)
def test_mask_secret(desc, secret, visible, expected):
    assert mask_secret(secret, visible) == expected


def test_mask_secret_default_visible():
    result = mask_secret("0123456789ABCDEF")
    assert result.startswith("0123")
    assert result.endswith("CDEF")
    assert "*" in result


# -- _adjust_scroll -----------------------------------------------------------


@pytest.mark.parametrize(
    "desc, cursor, top, visible, expected",
    [
        ("above", 2, 5, 10, 2),
        ("below", 15, 0, 10, 6),
        ("within", 5, 0, 10, 0),
        ("top-edge", 0, 0, 10, 0),
        ("bottom-edge", 9, 0, 10, 0),
    ],
)
def test_adjust_scroll(desc, cursor, top, visible, expected):
    assert _adjust_scroll(cursor, top, visible) == expected


# -- _truncate_secret ---------------------------------------------------------


@pytest.mark.parametrize(
    "desc, text, max_width, expected",
    [
        ("no-trunc", "short", 10, "short"),
        ("with-ellipsis", "ABCDEFGHIJ", 7, "ABCD..."),
        ("boundary", "ABCDE", 5, "ABCDE"),
        ("eq-ellipsis", "ABCDEFGHIJ", 3, "ABC"),
        ("lt-ellipsis", "ABCDEFGHIJ", 2, "AB"),
    ],
)
def test_truncate_secret(desc, text, max_width, expected):
    assert _truncate_secret(text, max_width) == expected


# -- _truncate_path -----------------------------------------------------------


@pytest.mark.parametrize(
    "desc, path, max_width, expected",
    [
        ("no-trunc", "/tmp/short", 20, "/tmp/short"),
        (
            "middle-trunc",
            "/home/user/very/long/path.txt",
            15,
            "/home/...th.txt",
        ),
        ("boundary", "/tmp/a", 6, "/tmp/a"),
        ("eq-ellipsis", "/home/user/path", 3, "/ho"),
        ("lt-ellipsis", "/home/user/path", 2, "/h"),
    ],
)
def test_truncate_path(desc, path, max_width, expected):
    result = _truncate_path(path, max_width)
    assert len(result) <= max_width
    if max_width > 3 and len(path) > max_width:
        assert "..." in result


# -- _handle_key --------------------------------------------------------------


def _make_findings_and_selected(n=3):
    findings = [
        Finding(
            file_path="/tmp/f.txt",
            secret=f"secret{i}",
            detector_name="Generic",
        )
        for i in range(n)
    ]
    selected = [True] * n
    return findings, selected


@pytest.mark.parametrize("desc, key", [("KEY_UP", curses.KEY_UP), ("k", ord("k"))])
def test_handle_key_move_up(desc, key):
    findings, selected = _make_findings_and_selected()
    cursor, reveal, result = _handle_key(
        key, findings, selected, cursor=1, reveal=False
    )
    assert cursor == 0
    assert result is None


@pytest.mark.parametrize("desc, key", [("KEY_DOWN", curses.KEY_DOWN), ("j", ord("j"))])
def test_handle_key_move_down(desc, key):
    findings, selected = _make_findings_and_selected()
    cursor, reveal, result = _handle_key(
        key, findings, selected, cursor=0, reveal=False
    )
    assert cursor == 1
    assert result is None


def test_handle_key_space_toggle():
    findings, selected = _make_findings_and_selected()
    assert selected[0] is True
    cursor, reveal, result = _handle_key(
        ord(" "), findings, selected, cursor=0, reveal=False
    )
    assert selected[0] is False
    assert result is None


def test_handle_key_select_all():
    findings, selected = _make_findings_and_selected()
    # all selected → deselect all
    _handle_key(ord("a"), findings, selected, cursor=0, reveal=False)
    assert all(s is False for s in selected)
    # none selected → select all
    _handle_key(ord("a"), findings, selected, cursor=0, reveal=False)
    assert all(s is True for s in selected)


def test_handle_key_category_toggle():
    findings = [
        Finding(file_path="/tmp/f.txt", secret="s1", detector_name="AWS"),
        Finding(file_path="/tmp/f.txt", secret="s2", detector_name="AWS"),
        Finding(file_path="/tmp/f.txt", secret="s3", detector_name="GitHub"),
    ]
    selected = [True, True, True]
    # toggle AWS category off (cursor=0 points to AWS)
    _handle_key(ord("t"), findings, selected, cursor=0, reveal=False)
    assert selected == [False, False, True]
    # toggle AWS category back on
    _handle_key(ord("t"), findings, selected, cursor=0, reveal=False)
    assert selected == [True, True, True]


def test_handle_key_reveal_toggle():
    findings, selected = _make_findings_and_selected()
    cursor, reveal, result = _handle_key(
        ord("r"), findings, selected, cursor=0, reveal=False
    )
    assert reveal is True
    assert result is None


def test_handle_key_enter():
    findings, selected = _make_findings_and_selected()
    selected[1] = False
    cursor, reveal, result = _handle_key(
        ord("\n"), findings, selected, cursor=0, reveal=False
    )
    assert result is not None
    assert len(result) == 2
    assert findings[0] in result
    assert findings[2] in result


def test_handle_key_quit():
    findings, selected = _make_findings_and_selected()
    cursor, reveal, result = _handle_key(
        ord("q"), findings, selected, cursor=0, reveal=False
    )
    assert result == []


def test_handle_key_unknown():
    findings, selected = _make_findings_and_selected()
    cursor, reveal, result = _handle_key(
        ord("z"), findings, selected, cursor=0, reveal=False
    )
    assert cursor == 0
    assert result is None


def test_handle_key_cursor_clamp_top():
    findings, selected = _make_findings_and_selected()
    cursor, reveal, result = _handle_key(
        curses.KEY_UP, findings, selected, cursor=0, reveal=False
    )
    assert cursor == 0


def test_handle_key_cursor_clamp_bottom():
    findings, selected = _make_findings_and_selected()
    cursor, reveal, result = _handle_key(
        curses.KEY_DOWN,
        findings,
        selected,
        cursor=len(findings) - 1,
        reveal=False,
    )
    assert cursor == len(findings) - 1
