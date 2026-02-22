"""Tests for trufflehog_redactor.redactor."""

import logging
import os
import stat

from trufflehog_redactor.parser import Finding
from trufflehog_redactor.redactor import (
    _group_by_file,
    _validate_file,
    apply_redactions,
    generate_diffs,
    generate_replacements,
)

# -- _group_by_file -----------------------------------------------------------


def test_group_by_file_single(make_finding):
    f = make_finding()
    result = _group_by_file([f])
    assert list(result.keys()) == [f.file_path]
    assert result[f.file_path] == [f]


def test_group_by_file_multiple(make_finding):
    f1 = make_finding(file_path="/a.txt", secret="s1")
    f2 = make_finding(file_path="/b.txt", secret="s2")
    f3 = make_finding(file_path="/a.txt", secret="s3")
    result = _group_by_file([f1, f2, f3])
    assert set(result.keys()) == {"/a.txt", "/b.txt"}
    assert len(result["/a.txt"]) == 2
    assert len(result["/b.txt"]) == 1


def test_group_by_file_empty():
    assert _group_by_file([]) == {}


# -- _validate_file -----------------------------------------------------------


def test_validate_file_regular(tmp_path):
    f = tmp_path / "regular.txt"
    f.write_text("content")
    assert _validate_file(str(f)) is True


def test_validate_file_symlink(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("content")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    assert _validate_file(str(link)) is False


def test_validate_file_missing(tmp_path):
    assert _validate_file(str(tmp_path / "nonexistent.txt")) is False


def test_validate_file_hardlink_warns(tmp_path, caplog):
    f = tmp_path / "original.txt"
    f.write_text("content")
    hardlink = tmp_path / "hardlink.txt"
    os.link(str(f), str(hardlink))
    with caplog.at_level(logging.WARNING):
        result = _validate_file(str(f))
    assert result is True
    assert "hard links" in caplog.text


# -- generate_replacements ----------------------------------------------------


def test_generate_replacements_basic(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("my secret is TOPSECRET123 here")
    finding = Finding(file_path=str(f), secret="TOPSECRET123", detector_name="Generic")
    result = generate_replacements([finding], "[REDACTED]")
    assert str(f) in result
    original, redacted = result[str(f)]
    assert "TOPSECRET123" in original
    assert "[REDACTED]" in redacted
    assert "TOPSECRET123" not in redacted


def test_generate_replacements_asterisk_default(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("secret=ABC123")
    finding = Finding(file_path=str(f), secret="ABC123", detector_name="Generic")
    result = generate_replacements([finding], "")
    _, redacted = result[str(f)]
    assert "******" in redacted


def test_generate_replacements_longest_first(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("token=ABCDEF and also ABCDEFGHIJ")
    short = Finding(file_path=str(f), secret="ABCDEF", detector_name="G")
    long = Finding(file_path=str(f), secret="ABCDEFGHIJ", detector_name="G")
    result = generate_replacements([short, long], "[R]")
    _, redacted = result[str(f)]
    # The long secret should have been replaced first
    assert redacted == "token=[R] and also [R]"


def test_generate_replacements_no_change_skipped(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("nothing here")
    finding = Finding(file_path=str(f), secret="notpresent", detector_name="G")
    result = generate_replacements([finding], "[R]")
    assert result == {}


def test_generate_replacements_skips_symlink(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("secret=ABC")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    finding = Finding(file_path=str(link), secret="ABC", detector_name="G")
    result = generate_replacements([finding], "[R]")
    assert result == {}


def test_generate_replacements_skips_missing(tmp_path):
    finding = Finding(
        file_path=str(tmp_path / "gone.txt"), secret="ABC", detector_name="G"
    )
    result = generate_replacements([finding], "[R]")
    assert result == {}


def test_generate_replacements_unicode_error(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(b"\x80\x81\x82\x83")
    finding = Finding(file_path=str(f), secret="ABC", detector_name="G")
    result = generate_replacements([finding], "[R]")
    assert result == {}


# -- generate_diffs -----------------------------------------------------------


def test_generate_diffs_without_masking():
    replacements = {"/tmp/a.txt": ("secret=ABC\n", "secret=[R]\n")}
    diff = generate_diffs(replacements)
    assert "-secret=ABC" in diff
    assert "+secret=[R]" in diff


def test_generate_diffs_with_masking():
    replacements = {"/tmp/a.txt": ("secret=ABCDEFGHIJKL\n", "secret=[R]\n")}
    findings = [
        Finding(file_path="/tmp/a.txt", secret="ABCDEFGHIJKL", detector_name="G")
    ]
    diff = generate_diffs(replacements, findings=findings)
    # The raw secret should be masked in the diff
    assert "ABCDEFGHIJKL" not in diff
    assert "ABCD" in diff  # first 4 visible chars from mask_secret


def test_generate_diffs_sorted_by_path():
    replacements = {
        "/tmp/z.txt": ("s=Z\n", "s=[R]\n"),
        "/tmp/a.txt": ("s=A\n", "s=[R]\n"),
    }
    diff = generate_diffs(replacements)
    pos_a = diff.index("/tmp/a.txt")
    pos_z = diff.index("/tmp/z.txt")
    assert pos_a < pos_z


# -- apply_redactions ---------------------------------------------------------


def test_apply_redactions_writes_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("original content with SECRET")
    replacements = {
        str(f): ("original content with SECRET", "original content with [R]")
    }
    count = apply_redactions(replacements)
    assert count == 1
    assert f.read_text() == "original content with [R]"


def test_apply_redactions_preserves_permissions(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("SECRET")
    os.chmod(str(f), 0o755)
    replacements = {str(f): ("SECRET", "[R]")}
    apply_redactions(replacements)
    assert stat.S_IMODE(os.stat(str(f)).st_mode) == 0o755


def test_apply_redactions_multiple_files(tmp_path):
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("SECRET1")
    f2.write_text("SECRET2")
    replacements = {
        str(f1): ("SECRET1", "[R1]"),
        str(f2): ("SECRET2", "[R2]"),
    }
    count = apply_redactions(replacements)
    assert count == 2
    assert f1.read_text() == "[R1]"
    assert f2.read_text() == "[R2]"
