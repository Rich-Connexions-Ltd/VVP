"""Hierarchical phase timing for verification pipeline instrumentation.

Sprint 76: PhaseTimer moved to common/common/vvp/timing.py for shared use
across issuer and verifier. This module re-exports for backward compatibility.
"""

from common.vvp.timing import PhaseTimer  # noqa: F401

__all__ = ["PhaseTimer"]
