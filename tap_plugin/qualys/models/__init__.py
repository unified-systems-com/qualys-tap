"""Qualys-owned entity types (specs/spec-qualys-v0.md, Model catalog)."""

from .detection import QualysDetection
from .host import QualysHost
from .qid import QualysQid
from .scan_run import QualysScanRun
from .subscription import QualysSubscription

__all__ = [
    "QualysDetection",
    "QualysHost",
    "QualysQid",
    "QualysScanRun",
    "QualysSubscription",
]
