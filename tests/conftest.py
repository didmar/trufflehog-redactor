"""Shared fixtures for the test suite."""

import json

import pytest

from trufflehog_redactor.parser import Finding


@pytest.fixture()
def make_finding():
    """Factory that creates Finding instances with sensible defaults."""

    def _make(
        file_path="/tmp/test.txt",
        secret="SUPERSECRETKEY1234",
        detector_name="Generic",
    ):
        return Finding(file_path=file_path, secret=secret, detector_name=detector_name)

    return _make


@pytest.fixture()
def make_json_line():
    """Factory that builds a TruffleHog JSON line string."""

    def _make(raw="SUPERSECRETKEY1234", detector="Generic", file_path="/tmp/test.txt"):
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

    return _make
