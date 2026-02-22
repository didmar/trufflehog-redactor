"""End-to-end integration tests that invoke the CLI as a subprocess."""

import json
import os
import stat
import subprocess
import sys

CMD = [sys.executable, "-m", "trufflehog_redactor"]


def make_json_line(raw, detector, file_path):
    """Build one TruffleHog JSON line."""
    obj = {
        "Raw": raw,
        "DetectorName": detector,
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": file_path,
                }
            }
        },
    }
    return json.dumps(obj)


def run_redactor(json_lines, extra_args=None):
    """Run the CLI in pipe + --no-confirm mode and return the CompletedProcess."""
    args = CMD + ["--no-confirm"] + (extra_args or [])
    return subprocess.run(
        args,
        input=json_lines,
        capture_output=True,
        text=True,
    )


# ── Basic redaction flow ─────────────────────────────────────────────


class TestBasicRedaction:
    def test_basic_redaction(self, tmp_path):
        """One secret, default asterisk placeholder, verify file modified and stdout."""
        secret = "SUPERSECRETKEY1234"
        target = tmp_path / "creds.txt"
        target.write_text(f"password={secret}\n")

        line = make_json_line(secret, "Generic", str(target))
        result = run_redactor(line + "\n")

        assert result.returncode == 0
        assert "Redacted secrets in 1 file(s)." in result.stdout
        content = target.read_text()
        assert secret not in content
        assert "*" in content

    def test_custom_placeholder(self, tmp_path):
        """--placeholder '[REDACTED]' replaces the secret with that string."""
        secret = "MY_API_KEY_12345"
        target = tmp_path / "config.yaml"
        target.write_text(f"api_key: {secret}\n")

        line = make_json_line(secret, "Generic", str(target))
        result = run_redactor(line + "\n", extra_args=["--placeholder", "[REDACTED]"])

        assert result.returncode == 0
        content = target.read_text()
        assert content == "api_key: [REDACTED]\n"

    def test_default_placeholder_asterisks_match_length(self, tmp_path):
        """Asterisks count equals the secret length."""
        secret = "abcdef"
        target = tmp_path / "f.txt"
        target.write_text(f"key={secret}\n")

        line = make_json_line(secret, "Generic", str(target))
        run_redactor(line + "\n")

        content = target.read_text()
        assert content == "key=******\n"

    def test_multiple_secrets_in_one_file(self, tmp_path):
        """Two secrets (one a substring of the other), longest-first replacement."""
        short_secret = "SECRET"
        long_secret = "SUPERSECRETLONG"
        target = tmp_path / "multi.txt"
        target.write_text(f"a={long_secret}\nb={short_secret}\n")

        lines = (
            make_json_line(short_secret, "Generic", str(target))
            + "\n"
            + make_json_line(long_secret, "Generic", str(target))
            + "\n"
        )
        result = run_redactor(lines, extra_args=["--placeholder", "[REDACTED]"])

        assert result.returncode == 0
        content = target.read_text()
        assert content == "a=[REDACTED]\nb=[REDACTED]\n"

    def test_multiple_files(self, tmp_path):
        """Secrets across two files, both redacted."""
        s1, s2 = "SECRET_ONE", "SECRET_TWO"
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text(f"val={s1}\n")
        f2.write_text(f"val={s2}\n")

        lines = (
            make_json_line(s1, "Generic", str(f1))
            + "\n"
            + make_json_line(s2, "Generic", str(f2))
            + "\n"
        )
        result = run_redactor(lines, extra_args=["--placeholder", "XXX"])

        assert result.returncode == 0
        assert "Redacted secrets in 2 file(s)." in result.stdout
        assert f1.read_text() == "val=XXX\n"
        assert f2.read_text() == "val=XXX\n"

    def test_multiline_file_content_preserved(self, tmp_path):
        """Only the secret line changes; rest of the file stays intact."""
        secret = "LEAK_HERE"
        target = tmp_path / "big.txt"
        target.write_text("line1\nline2\npassword=LEAK_HERE\nline4\n")

        line = make_json_line(secret, "Generic", str(target))
        run_redactor(line + "\n", extra_args=["--placeholder", "XXX"])

        assert target.read_text() == "line1\nline2\npassword=XXX\nline4\n"

    def test_duplicate_findings_deduplicated(self, tmp_path):
        """Same JSON line twice -> 'Found 1 unique secret(s)'."""
        secret = "DUP_SECRET"
        target = tmp_path / "dup.txt"
        target.write_text(f"x={secret}\n")

        line = make_json_line(secret, "Generic", str(target))
        result = run_redactor(line + "\n" + line + "\n")

        assert "Found 1 unique secret(s)" in result.stdout


# ── Dry run ──────────────────────────────────────────────────────────


class TestDryRun:
    def test_dry_run_does_not_modify_file(self, tmp_path):
        """File unchanged; stdout has diff + summary."""
        secret = "DONT_TOUCH_ME"
        target = tmp_path / "safe.txt"
        target.write_text(f"key={secret}\n")

        line = make_json_line(secret, "Generic", str(target))
        result = run_redactor(line + "\n", extra_args=["--dry-run"])

        assert result.returncode == 0
        # File must be untouched
        assert target.read_text() == f"key={secret}\n"
        assert "Dry run:" in result.stdout
        assert "1 file(s) would be modified" in result.stdout

    def test_dry_run_with_custom_placeholder(self, tmp_path):
        """Diff shows custom placeholder; file unchanged."""
        secret = "FRAGILE_KEY"
        target = tmp_path / "cfg.txt"
        target.write_text(f"token={secret}\n")

        line = make_json_line(secret, "Generic", str(target))
        result = run_redactor(
            line + "\n",
            extra_args=["--dry-run", "--placeholder", "[REMOVED]"],
        )

        assert target.read_text() == f"token={secret}\n"
        assert "Dry run:" in result.stdout


# ── Edge cases / no-op paths ────────────────────────────────────────


class TestEdgeCases:
    def test_no_secrets_found_empty_input(self):
        """Empty stdin -> 'No secrets found'."""
        result = run_redactor("")
        assert result.returncode == 0
        assert "No secrets found" in result.stdout

    def test_no_secrets_found_invalid_json(self):
        """Garbage input -> 'No secrets found'."""
        result = run_redactor("this is not json\n{bad json too}\n")
        assert result.returncode == 0
        assert "No secrets found" in result.stdout

    def test_secret_not_in_file(self, tmp_path):
        """Valid JSON but secret not actually in the file -> 'No matching secrets'."""
        target = tmp_path / "clean.txt"
        target.write_text("nothing secret here\n")

        line = make_json_line("DOES_NOT_EXIST", "Generic", str(target))
        result = run_redactor(line + "\n")

        assert result.returncode == 0
        assert "No matching secrets" in result.stdout

    def test_missing_file_graceful(self, tmp_path):
        """Finding references nonexistent file -> no crash."""
        missing = str(tmp_path / "ghost.txt")
        line = make_json_line("SOME_SECRET", "Generic", missing)
        result = run_redactor(line + "\n")

        assert result.returncode == 0
        # Should not crash; either "No matching secrets" or warning on stderr
        assert "No matching secrets" in result.stdout


# ── Symlinks ─────────────────────────────────────────────────────────


class TestSymlinks:
    def test_symlink_skipped(self, tmp_path):
        """Finding points at a symlink -> skipped, target unchanged."""
        secret = "SYMLINK_SECRET"
        real = tmp_path / "real.txt"
        real.write_text(f"key={secret}\n")
        link = tmp_path / "link.txt"
        link.symlink_to(real)

        line = make_json_line(secret, "Generic", str(link))
        result = run_redactor(line + "\n")

        assert result.returncode == 0
        # Real file must not be modified since the finding pointed at the symlink
        assert real.read_text() == f"key={secret}\n"
        # Stderr should mention skipping
        assert (
            "Skipping symlink" in result.stderr
            or "No matching secrets" in result.stdout
        )

    def test_symlink_target_redacted_via_real_path(self, tmp_path):
        """Real file finding -> real file redacted."""
        secret = "REAL_SECRET"
        real = tmp_path / "real.txt"
        real.write_text(f"val={secret}\n")
        link = tmp_path / "alias.txt"
        link.symlink_to(real)

        # Finding references the real path, not the symlink
        line = make_json_line(secret, "Generic", str(real))
        result = run_redactor(line + "\n", extra_args=["--placeholder", "XXX"])

        assert result.returncode == 0
        assert real.read_text() == "val=XXX\n"
        # Symlink resolves to the same (now-redacted) content
        assert link.read_text() == "val=XXX\n"

    def test_symlink_and_regular_file_mixed(self, tmp_path):
        """One symlink finding + one regular finding -> only regular file redacted."""
        s_sym, s_reg = "SYM_SECRET", "REG_SECRET"
        real = tmp_path / "real.txt"
        real.write_text(f"a={s_sym}\n")
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        regular = tmp_path / "normal.txt"
        regular.write_text(f"b={s_reg}\n")

        lines = (
            make_json_line(s_sym, "Generic", str(link))
            + "\n"
            + make_json_line(s_reg, "Generic", str(regular))
            + "\n"
        )
        result = run_redactor(lines, extra_args=["--placeholder", "XXX"])

        assert result.returncode == 0
        # Symlink finding skipped, so real file keeps the secret
        assert s_sym in real.read_text()
        # Regular file redacted
        assert regular.read_text() == "b=XXX\n"


# ── Hard links ───────────────────────────────────────────────────────


class TestHardlinks:
    def test_hardlink_redacted_other_link_retains_old_content(self, tmp_path):
        """os.replace gives new inode; other hard link keeps old content."""
        secret = "HARDLINK_SECRET"
        original = tmp_path / "original.txt"
        original.write_text(f"key={secret}\n")
        other = tmp_path / "other.txt"
        os.link(str(original), str(other))

        line = make_json_line(secret, "Generic", str(original))
        result = run_redactor(line + "\n", extra_args=["--placeholder", "XXX"])

        assert result.returncode == 0
        # Targeted path is redacted (new inode via os.replace)
        assert original.read_text() == "key=XXX\n"
        # Other hard link still points at the old inode
        assert other.read_text() == f"key={secret}\n"
        # Inodes should now differ
        assert os.stat(str(original)).st_ino != os.stat(str(other)).st_ino

    def test_hardlink_both_paths_in_findings(self, tmp_path):
        """Both hard link paths in findings -> both redacted independently."""
        secret = "SHARED_SECRET"
        path_a = tmp_path / "a.txt"
        path_a.write_text(f"val={secret}\n")
        path_b = tmp_path / "b.txt"
        os.link(str(path_a), str(path_b))

        lines = (
            make_json_line(secret, "Generic", str(path_a))
            + "\n"
            + make_json_line(secret, "Generic", str(path_b))
            + "\n"
        )
        result = run_redactor(lines, extra_args=["--placeholder", "XXX"])

        assert result.returncode == 0
        assert path_a.read_text() == "val=XXX\n"
        assert path_b.read_text() == "val=XXX\n"


# ── Misc ─────────────────────────────────────────────────────────────


class TestMisc:
    def test_preserves_file_permissions(self, tmp_path):
        """File with 0o755 keeps that mode after redaction."""
        secret = "PERM_SECRET"
        target = tmp_path / "script.sh"
        target.write_text(f"#!/bin/sh\nTOKEN={secret}\n")
        target.chmod(0o755)

        line = make_json_line(secret, "Generic", str(target))
        run_redactor(line + "\n", extra_args=["--placeholder", "XXX"])

        assert target.read_text() == "#!/bin/sh\nTOKEN=XXX\n"
        mode = stat.S_IMODE(target.stat().st_mode)
        assert mode == 0o755

    def test_exit_code_zero_on_success(self, tmp_path):
        """Return code is 0 on successful redaction."""
        secret = "EXIT_CODE_SECRET"
        target = tmp_path / "rc.txt"
        target.write_text(f"x={secret}\n")

        line = make_json_line(secret, "Generic", str(target))
        result = run_redactor(line + "\n")

        assert result.returncode == 0
