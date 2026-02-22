"""Tests for trufflehog_redactor.parser."""

import io

import pytest

from trufflehog_redactor.parser import _valid_finding, parse_findings

# -- _valid_finding -----------------------------------------------------------


def test_valid_finding_accepts():
    assert _valid_finding("secret123", "/tmp/test.txt") is True


@pytest.mark.parametrize(
    "desc, raw, file_path",
    [
        ("empty-raw", "", "/tmp/test.txt"),  # empty raw
        ("empty-path", "secret", ""),  # empty path
        ("non-string-raw", 123, "/tmp/test.txt"),  # non-string raw
        ("non-string-path", "secret", 42),  # non-string path
        ("none-raw", None, "/tmp/test.txt"),  # None raw
        ("none-path", "secret", None),  # None path
        ("null-byte-in-path", "secret", "/tmp/\x00bad"),  # null byte in path
    ],
)
def test_valid_finding_rejects(desc, raw, file_path):
    assert _valid_finding(raw, file_path) is False


# -- parse_findings -----------------------------------------------------------


def test_parse_findings_valid_lines(make_json_line):
    stream = io.StringIO(make_json_line() + "\n")
    findings = parse_findings(stream)
    assert len(findings) == 1
    assert findings[0].secret == "SUPERSECRETKEY1234"
    assert findings[0].file_path == "/tmp/test.txt"
    assert findings[0].detector_name == "Generic"


def test_parse_findings_empty_input():
    findings = parse_findings(io.StringIO(""))
    assert findings == []


def test_parse_findings_blank_lines_skipped(make_json_line):
    stream = io.StringIO("\n\n" + make_json_line() + "\n\n")
    findings = parse_findings(stream)
    assert len(findings) == 1


def test_parse_findings_invalid_json_skipped(make_json_line):
    stream = io.StringIO("not json\n" + make_json_line() + "\n")
    findings = parse_findings(stream)
    assert len(findings) == 1


@pytest.mark.parametrize(
    "desc, json_str",
    [
        ("No SourceMetadata", '{"Raw": "secret"}'),
        ("No Data", '{"Raw": "secret", "SourceMetadata": {}}'),
        ("No Filesystem", '{"Raw": "secret", "SourceMetadata": {"Data": {}}}'),
        (
            "No file",
            '{"Raw": "secret", "SourceMetadata": {"Data": {"Filesystem": {}}}}',
        ),
    ],
)
def test_parse_findings_missing_fields_skipped(desc, json_str):
    findings = parse_findings(io.StringIO(json_str + "\n"))
    assert findings == []


def test_parse_findings_deduplication(make_json_line):
    line = make_json_line()
    stream = io.StringIO(line + "\n" + line + "\n")
    findings = parse_findings(stream)
    assert len(findings) == 1


def test_parse_findings_default_detector_name():
    import json

    obj = {
        "Raw": "secret123",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/tmp/f.txt"}}},
    }
    stream = io.StringIO(json.dumps(obj) + "\n")
    findings = parse_findings(stream)
    assert findings[0].detector_name == "Unknown"


@pytest.mark.parametrize(
    "desc, source_metadata",
    [
        ("source_metadata is not a dict", "not-a-dict"),
        ("Data is not a dict", {"Data": "not-a-dict"}),
        ("Filesystem is not a dict", {"Data": {"Filesystem": "not-a-dict"}}),
    ],
)
def test_parse_findings_non_dict_metadata(desc, source_metadata):
    import json

    obj = {"Raw": "secret123", "SourceMetadata": source_metadata}
    stream = io.StringIO(json.dumps(obj) + "\n")
    findings = parse_findings(stream)
    assert findings == []
