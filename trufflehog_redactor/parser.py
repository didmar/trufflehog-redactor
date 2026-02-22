"""Parse TruffleHog JSON output from stdin."""

import json
import sys
from dataclasses import dataclass
from typing import IO, List, Optional, Set, Tuple


@dataclass
class Finding:
    file_path: str
    secret: str
    detector_name: str


def parse_findings(stream: Optional[IO[str]] = None) -> List[Finding]:
    """Read TruffleHog JSON lines from a stream and return deduplicated findings."""
    if stream is None:
        stream = sys.stdin

    seen: Set[Tuple[str, str]] = set()
    findings: List[Finding] = []

    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        raw = obj.get("Raw", "")
        detector = obj.get("DetectorName", "Unknown")
        file_path = ""

        source_meta = obj.get("SourceMetadata", {})
        data = source_meta.get("Data", {}) if isinstance(source_meta, dict) else {}
        filesystem = data.get("Filesystem", {}) if isinstance(data, dict) else {}
        file_path = filesystem.get("file", "") if isinstance(filesystem, dict) else ""

        if not _valid_finding(raw, file_path):
            continue

        key = (file_path, raw)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            Finding(file_path=file_path, secret=raw, detector_name=detector)
        )

    return findings


def _valid_finding(raw: object, file_path: object) -> bool:
    """Return True if raw and file_path are usable non-empty strings."""
    return (
        isinstance(raw, str)
        and isinstance(file_path, str)
        and bool(raw)
        and bool(file_path)
        and "\x00" not in file_path
    )
