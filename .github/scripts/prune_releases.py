#!/usr/bin/env python3
"""Retain published vx.y.z releases; preserve tags, drafts and prereleases."""
import argparse
from datetime import datetime
import json
import re
import subprocess

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)


def valid_tag(tag):
    return isinstance(tag, str) and TAG.fullmatch(tag) is not None


def select_releases_to_delete(releases, keep=5):
    if keep < 1:
        raise ValueError("keep must be positive")
    candidates = []
    for release in releases:
        if (release.get("draft") or release.get("prerelease")
                or not valid_tag(release.get("tag_name"))):
            continue
        # Validate the entire snapshot before making any destructive request.
        if not isinstance(release.get("published_at"), str):
            raise ValueError("missing publication date")
        published = datetime.fromisoformat(release["published_at"].replace("Z", "+00:00"))
        if published.tzinfo is None or not isinstance(release["id"], int) or release["id"] < 1:
            raise ValueError("invalid published release metadata")
        candidates.append((published, release["id"], release))
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [release for _, _, release in candidates[keep:]]


def prune(repo, keep=5):
    # Explicit pagination: repositories with >100 releases must also be pruned.
    result = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repo}/releases?per_page=100"],
        check=True, capture_output=True, text=True,
    )
    pages = json.loads(result.stdout)
    releases = [release for page in pages for release in page]
    expired = select_releases_to_delete(releases, keep)
    for release in expired:
        print(f"Deleting release {release['tag_name']} (keeping Git tag)", flush=True)
        result = subprocess.run(
            ["gh", "api", "--method", "DELETE", f"repos/{repo}/releases/{release['id']}"],
            capture_output=True, text=True,
        )
        # Another tag workflow may already have deleted the same old release.
        # Only an actual 404 is idempotent; authorization/server errors fail CI.
        if result.returncode and "(HTTP 404)" not in result.stderr:
            raise RuntimeError(result.stderr)
    print(f"Retention complete: {len(expired)} expired releases processed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-tag")
    validate.add_argument("tag")
    cleanup = commands.add_parser("prune")
    cleanup.add_argument("--repo", required=True)
    cleanup.add_argument("--keep", type=int, default=5)
    args = parser.parse_args()
    if args.command == "validate-tag":
        if not valid_tag(args.tag):
            parser.error("expected a stable tag such as v1.2.3 (no suffix or leading zeros)")
    else:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
            parser.error("expected OWNER/REPOSITORY")
        prune(args.repo, args.keep)


if __name__ == "__main__":
    main()
