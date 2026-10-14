#!/usr/bin/env python3
"""Extract AR_SERVER_INFO_* constants from Constants.java and emit JSON for hitt.sh.

Default source: GitHub API (private RemedyPlatform/ars-serverj @ 10R).
Set GITHUB_TOKEN or GH_TOKEN with repo read access, or pass a local file path.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PATTERN = re.compile(
    r"public\s+(?:static\s+final|final\s+static)\s+int\s+(AR_SERVER_INFO_\w+)\s*=\s*(-?\d+)\s*;"
)

DEFAULT_GITHUB_OWNER = "RemedyPlatform"
DEFAULT_GITHUB_REPO = "ars-serverj"
DEFAULT_GITHUB_REF = "10R"
DEFAULT_GITHUB_PATH = (
    "domain/src/main/java/com/bmc/arsys/domain/constants/Constants.java"
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


def resolve_repo_path(path: str | Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return (REPO_ROOT / p).resolve()


def parse_constants_text(text: str) -> dict[str, int]:
    entries: dict[str, int] = {}
    for name, value in PATTERN.findall(text):
        entries[name] = int(value)
    return entries


def github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def fetch_constants_from_github(
    owner: str,
    repo: str,
    ref: str,
    path: str,
    token: str,
) -> str:
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        f"?ref={urllib.parse.quote(ref, safe='')}"
    )
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        print(
            f"error: GitHub API HTTP {exc.code} for {owner}/{repo}@{ref}: {body}",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    except urllib.error.URLError as exc:
        print(f"error: GitHub API request failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    content_b64 = payload.get("content")
    if not content_b64:
        print(
            "error: GitHub API returned no file content (check path, ref, and token access).",
            file=sys.stderr,
        )
        raise SystemExit(1)

    raw = base64.b64decode(content_b64.replace("\n", ""), validate=False)
    return raw.decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Run using this file's path from any working directory. "
            "Paths for the local java file and -o/--out are relative to the "
            f"helix-tools repo root ({REPO_ROOT})."
        ),
    )
    parser.add_argument(
        "java_path",
        nargs="?",
        help="Optional local Constants.java (skips GitHub); relative to repo root",
    )
    parser.add_argument("--owner", default=DEFAULT_GITHUB_OWNER)
    parser.add_argument("--repo", default=DEFAULT_GITHUB_REPO)
    parser.add_argument("--ref", default=DEFAULT_GITHUB_REF)
    parser.add_argument("--path", default=DEFAULT_GITHUB_PATH, dest="github_path")
    parser.add_argument(
        "-o",
        "--out",
        help="Write JSON here instead of stdout (relative to repo root)",
    )
    args = parser.parse_args()

    if args.java_path:
        java_path = resolve_repo_path(args.java_path)
        if not java_path.is_file():
            print(f"error: file not found: {java_path}", file=sys.stderr)
            return 1
        text = java_path.read_text(encoding="utf-8", errors="replace")
    else:
        token = github_token()
        if not token:
            print(
                "error: set GITHUB_TOKEN or GH_TOKEN for GitHub fetch, "
                "or pass a local Constants.java path.",
                file=sys.stderr,
            )
            return 1
        text = fetch_constants_from_github(
            args.owner, args.repo, args.ref, args.github_path, token
        )

    by_name = parse_constants_text(text)
    if not by_name:
        print("error: no AR_SERVER_INFO_* constants found", file=sys.stderr)
        return 1

    items = [
        {"name": name, "id": cid}
        for name, cid in sorted(by_name.items(), key=lambda item: (item[1], item[0]))
    ]
    out_json = json.dumps(items, separators=(",", ":"))
    if args.out:
        out_path = resolve_repo_path(args.out)
        out_path.write_text(out_json + "\n", encoding="utf-8", newline="\n")
        print(f"Wrote {out_path} ({len(items)} name:id pairs)", file=sys.stderr)
    else:
        print(out_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
