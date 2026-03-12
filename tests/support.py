from __future__ import annotations

from open_range.build_config import BuildConfig


OFFLINE_BUILD_CONFIG = BuildConfig(validation_profile="graph_only")
OFFLINE_REFERENCE_BUILD_CONFIG = BuildConfig(validation_profile="no_necessity")
