"""Artifact source of truth for OpenRange builder templates.

Computes and verifies SHA256 hashes of template files to ensure they
haven't been modified unexpectedly.

Usage::

    python -m open_range.artifact_verify update   # regenerate hashes
    python -m open_range.artifact_verify verify    # check hashes match
    python -m open_range.artifact_verify           # defaults to verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


# Default templates directory relative to this file
_DEFAULT_TEMPLATES_DIR = Path(__file__).parent / "builder" / "templates"
_DEFAULT_HASHES_FILE = _DEFAULT_TEMPLATES_DIR / ".hashes.json"


def _hash_file(path: Path) -> str:
    """Compute SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_templates(templates_dir: Path) -> list[Path]:
    """Find all template files in the templates directory.

    Returns sorted list of template file paths (excludes .hashes.json
    and hidden files).
    """
    if not templates_dir.is_dir():
        return []
    templates = []
    for p in sorted(templates_dir.iterdir()):
        if p.is_file() and not p.name.startswith("."):
            templates.append(p)
    return templates


def compute_hashes(templates_dir: Path | None = None) -> dict[str, str]:
    """Compute SHA256 hashes for all template files.

    Args:
        templates_dir: Directory containing templates. Defaults to
            ``src/open_range/builder/templates/``.

    Returns:
        Dict mapping filename to SHA256 hex digest.
    """
    templates_dir = templates_dir or _DEFAULT_TEMPLATES_DIR
    hashes: dict[str, str] = {}
    for path in _find_templates(templates_dir):
        hashes[path.name] = _hash_file(path)
    return hashes


def update(
    templates_dir: Path | None = None,
    hashes_file: Path | None = None,
) -> dict[str, str]:
    """Regenerate the hash manifest file.

    Args:
        templates_dir: Directory containing templates.
        hashes_file: Path to write the JSON hash manifest.

    Returns:
        The computed hashes dict.
    """
    templates_dir = templates_dir or _DEFAULT_TEMPLATES_DIR
    hashes_file = hashes_file or (templates_dir / ".hashes.json")

    hashes = compute_hashes(templates_dir)
    hashes_file.parent.mkdir(parents=True, exist_ok=True)
    with open(hashes_file, "w") as f:
        json.dump(hashes, f, indent=2, sort_keys=True)
        f.write("\n")

    return hashes


def verify(
    templates_dir: Path | None = None,
    hashes_file: Path | None = None,
) -> dict[str, str]:
    """Verify current templates match stored hashes.

    Args:
        templates_dir: Directory containing templates.
        hashes_file: Path to the JSON hash manifest.

    Returns:
        Dict mapping filename to status string:
        - "ok" if hash matches
        - "modified" if hash differs
        - "missing" if file in manifest but not on disk
        - "new" if file on disk but not in manifest

    Raises:
        FileNotFoundError: If the hashes file does not exist.
    """
    templates_dir = templates_dir or _DEFAULT_TEMPLATES_DIR
    hashes_file = hashes_file or (templates_dir / ".hashes.json")

    if not hashes_file.exists():
        raise FileNotFoundError(
            f"Hash manifest not found: {hashes_file}. "
            f"Run 'python -m open_range.artifact_verify update' first."
        )

    with open(hashes_file) as f:
        stored_hashes: dict[str, str] = json.load(f)

    current_hashes = compute_hashes(templates_dir)

    results: dict[str, str] = {}

    # Check files in manifest
    for name, stored_hash in stored_hashes.items():
        if name not in current_hashes:
            results[name] = "missing"
        elif current_hashes[name] != stored_hash:
            results[name] = "modified"
        else:
            results[name] = "ok"

    # Check for new files not in manifest
    for name in current_hashes:
        if name not in stored_hashes:
            results[name] = "new"

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# ANSI color codes
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify or update OpenRange template artifact hashes",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="verify",
        choices=["verify", "update"],
        help="Action to perform (default: verify)",
    )
    parser.add_argument(
        "--templates-dir",
        type=Path,
        default=None,
        help="Templates directory (default: src/open_range/builder/templates/)",
    )
    args = parser.parse_args()

    if args.action == "update":
        hashes = update(templates_dir=args.templates_dir)
        print(f"{_GREEN}Updated hash manifest with {len(hashes)} files:{_RESET}")
        for name, h in sorted(hashes.items()):
            print(f"  {name}: {h[:16]}...")
        sys.exit(0)

    # verify
    try:
        results = verify(templates_dir=args.templates_dir)
    except FileNotFoundError as exc:
        print(f"{_RED}{exc}{_RESET}", file=sys.stderr)
        sys.exit(1)

    any_issues = False
    for name, status in sorted(results.items()):
        if status == "ok":
            print(f"  {_GREEN}OK{_RESET}       {name}")
        elif status == "modified":
            print(f"  {_RED}MODIFIED{_RESET}  {name}")
            any_issues = True
        elif status == "missing":
            print(f"  {_RED}MISSING{_RESET}   {name}")
            any_issues = True
        elif status == "new":
            print(f"  {_YELLOW}NEW{_RESET}      {name}")
            any_issues = True

    if any_issues:
        print(
            f"\n{_RED}Verification failed.{_RESET} "
            f"Run 'python -m open_range.artifact_verify update' to refresh."
        )
        sys.exit(1)
    else:
        print(f"\n{_GREEN}All templates verified.{_RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
