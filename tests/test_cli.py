"""Tests for trufflehog_redactor.cli."""

import io
import subprocess
from unittest.mock import patch

import pytest

from trufflehog_redactor.cli import _confirm_changes, _run_trufflehog

# -- _run_trufflehog ----------------------------------------------------------


@pytest.mark.parametrize("desc, returncode", [("rc0", 0), ("rc1", 1)])
def test_run_trufflehog_success(desc, returncode):
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout='{"Raw":"s"}\n', stderr=""
    )
    with patch("trufflehog_redactor.cli.subprocess.run", return_value=fake_result):
        stream = _run_trufflehog("/tmp/scan")
    assert isinstance(stream, io.StringIO)
    assert stream.read() == '{"Raw":"s"}\n'


def test_run_trufflehog_not_installed():
    with patch(
        "trufflehog_redactor.cli.subprocess.run", side_effect=FileNotFoundError
    ), pytest.raises(SystemExit):
        _run_trufflehog("/tmp/scan")


def test_run_trufflehog_error_exit_code():
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=2, stdout="", stderr="boom"
    )
    with patch("trufflehog_redactor.cli.subprocess.run", return_value=fake_result):
        with pytest.raises(SystemExit) as exc_info:
            _run_trufflehog("/tmp/scan")
        assert exc_info.value.code == 2


# -- _confirm_changes ---------------------------------------------------------


@pytest.mark.parametrize(
    "desc, user_input, expected",
    [
        ("Yes", "y\n", True),
        ("No", "n\n", False),
        ("Empty", "\n", False),
    ],
)
def test_confirm_changes(desc, user_input, expected):
    mock_tty = io.StringIO(user_input)
    with patch("builtins.open", return_value=mock_tty), patch("builtins.print"):
        assert _confirm_changes(3, "some diff") is expected


def test_confirm_changes_no_tty():
    with patch("builtins.open", side_effect=OSError("no tty")), patch("builtins.print"):
        with pytest.raises(SystemExit) as exc_info:
            _confirm_changes(3, "some diff")
        assert exc_info.value.code == 1
