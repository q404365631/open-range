from __future__ import annotations

from pathlib import Path

import open_range


def test_top_level_package_keeps_internal_runtime_and_sft_helpers_private() -> None:
    forbidden = {
        "ReferenceDrivenRuntime",
        "build_decision_prompt",
        "render_action_completion",
        "render_decision_prompt",
        "system_prompt_for_role",
    }

    exported = set(open_range.__all__)

    assert forbidden.isdisjoint(exported)
    assert all(not hasattr(open_range, name) for name in forbidden)


def test_public_docs_avoid_candidate_action_menu_language() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    docs = (
        repo_root / "README.md",
        repo_root / "docs" / "architecture.md",
        repo_root / "docs" / "how-an-episode-works.md",
        repo_root / "docs" / "training-data-spec.md",
    )

    for path in docs:
        text = path.read_text(encoding="utf-8").lower()
        assert "candidate_actions" not in text
        assert "candidate actions" not in text
