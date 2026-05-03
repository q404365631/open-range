"""OpenRange core errors."""

from __future__ import annotations


class OpenRangeError(Exception):
    """Base OpenRange error."""


class ManifestError(OpenRangeError):
    """Raised when a manifest is invalid."""


class PackError(OpenRangeError):
    """Raised when a pack cannot build an admissible world."""


class AdmissionError(OpenRangeError):
    """Raised when generated world artifacts fail admission."""


class StoreError(OpenRangeError):
    """Raised when snapshots cannot be loaded from storage."""
