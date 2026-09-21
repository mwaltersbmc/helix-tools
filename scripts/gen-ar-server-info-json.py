#!/usr/bin/env python3
"""Extract AR_SERVER_INFO_* constants from Constants.java and emit JSON for hitt.sh."""

import json
import re
import sys
from pathlib import Path

DEFAULT_JAVA = Path(
    r"w:\ars-serverj\domain\src\main\java\com\bmc\arsys\domain\constants\Constants.java"
)
PATTERN = re.compile(
    r"public\s+(?:static\s+final|final\s+static)\s+int\s+(AR_SERVER_INFO_\w+)\s*=\s*(-?\d+)\s*;"
)


def parse_constants(java_path: Path) -> dict[str, int]:
    text = java_path.read_text(encoding="utf-8", errors="replace")
    entries: dict[str, int] = {}
    for name, value in PATTERN.findall(text):
        entries[name] = int(value)
    return entries


def main() -> int:
    java_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_JAVA
    if not java_path.is_file():
        print(f"error: file not found: {java_path}", file=sys.stderr)
        return 1

    by_name = parse_constants(java_path)
    if not by_name:
        print("error: no AR_SERVER_INFO_* constants found", file=sys.stderr)
        return 1

    items = [
        {"name": name, "id": cid}
        for name, cid in sorted(by_name.items(), key=lambda item: (item[1], item[0]))
    ]
    print(json.dumps(items, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
