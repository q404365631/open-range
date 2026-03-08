"""Helpers for publishing validated OpenRange bundles to Hugging Face Spaces."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

SPACE_SNAPSHOT_PATH = Path("snapshots/deployed/spec.json")
_SPACE_ENV_VAR = "OPENRANGE_RUNTIME_SNAPSHOT"
_SPACE_ID_ENV_VARS = ("OPENRANGE_HF_SPACE", "HF_SPACE")
_HF_TOKEN_ENV_VARS = (
    "HF_TOKEN",
    "HUGGINGFACEHUB_API_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
)
_IGNORE_PATTERNS = (
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "*.pyc",
    ".DS_Store",
    "htmlcov",
    "build",
    "dist",
    "snapshots",
)


def resolve_space_id(space_id: str | None = None) -> str:
    """Resolve the target Hugging Face Space repo id."""
    resolved = (space_id or "").strip()
    if resolved:
        return resolved
    for env_name in _SPACE_ID_ENV_VARS:
        value = os.getenv(env_name, "").strip()
        if value:
            return value
    raise RuntimeError(
        "No Hugging Face Space configured. Pass --hf-space or set OPENRANGE_HF_SPACE."
    )


def resolve_hf_token(token: str | None = None) -> str:
    """Resolve an HF token from args or standard environment variables."""
    resolved = (token or "").strip()
    if resolved:
        return resolved
    for env_name in _HF_TOKEN_ENV_VARS:
        value = os.getenv(env_name, "").strip()
        if value:
            return value
    raise RuntimeError(
        "No Hugging Face token configured. Pass --hf-token or set HF_TOKEN."
    )


def stage_space_bundle(
    snapshot_path: str | Path,
    *,
    source_root: str | Path | None = None,
) -> Path:
    """Create a clean temporary Space bundle containing the validated snapshot."""
    snapshot_file = Path(snapshot_path).resolve()
    if not snapshot_file.exists():
        raise FileNotFoundError(f"Snapshot not found: {snapshot_file}")

    root = (
        Path(source_root).resolve()
        if source_root is not None
        else Path(__file__).resolve().parents[2]
    )
    bundle_dir = Path(tempfile.mkdtemp(prefix="openrange-hf-space-"))
    shutil.copytree(
        root,
        bundle_dir,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(*_IGNORE_PATTERNS),
    )

    target_snapshot = bundle_dir / SPACE_SNAPSHOT_PATH
    target_snapshot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(snapshot_file, target_snapshot)
    return bundle_dir


def deploy_validated_snapshot_to_space(
    snapshot_path: str | Path,
    *,
    space_id: str | None = None,
    token: str | None = None,
    create_repo: bool = True,
    private: bool | None = None,
    commit_message: str | None = None,
) -> Any:
    """Upload the current OpenRange app plus a validated snapshot to a Space."""
    from huggingface_hub import HfApi

    resolved_space = resolve_space_id(space_id)
    resolved_token = resolve_hf_token(token)
    bundle_dir = stage_space_bundle(snapshot_path)
    api = HfApi()

    try:
        if create_repo:
            api.create_repo(
                resolved_space,
                token=resolved_token,
                repo_type="space",
                exist_ok=True,
                private=private,
                space_sdk="docker",
            )
        api.add_space_variable(
            resolved_space,
            _SPACE_ENV_VAR,
            SPACE_SNAPSHOT_PATH.as_posix(),
            description="Validated snapshot served by OpenRange.",
            token=resolved_token,
        )
        return api.upload_folder(
            repo_id=resolved_space,
            repo_type="space",
            folder_path=bundle_dir,
            token=resolved_token,
            commit_message=commit_message
            or f"Deploy validated snapshot {Path(snapshot_path).stem}",
        )
    finally:
        shutil.rmtree(bundle_dir, ignore_errors=True)
