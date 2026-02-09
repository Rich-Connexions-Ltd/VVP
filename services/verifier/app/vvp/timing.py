"""Hierarchical phase timing for verification pipeline instrumentation.

Collects per-phase wall-clock timing aligned with both the dossier parsing
algorithm stages (knowledge/dossier-parsing-algorithm.md) and the verify.py
pipeline phases. Supports nested sub-phases via dotted names.

Timer names follow the convention:
    parent_phase.sub_phase

For example:
    dossier_parse              (parent)
    dossier_parse.format_detect (sub)
    dossier_parse.cesr_stream   (sub)
"""

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class PhaseTimer:
    """Collects per-phase timing for a single verification request.

    Thread-safety: Not thread-safe. Each request should have its own instance.
    """

    timings: Dict[str, float] = field(default_factory=dict)
    _stack: List[Tuple[str, float]] = field(default_factory=list)

    def start(self, phase: str) -> None:
        """Start timing a phase. Phases can be nested."""
        self._stack.append((phase, time.monotonic()))

    def stop(self) -> float:
        """Stop the most recently started phase and record its elapsed time.

        Returns:
            Elapsed time in milliseconds.
        """
        if not self._stack:
            logger.warning("PhaseTimer.stop() called with empty stack")
            return 0.0
        phase, start_time = self._stack.pop()
        elapsed_ms = (time.monotonic() - start_time) * 1000.0
        self.timings[phase] = elapsed_ms
        return elapsed_ms

    def record(self, phase: str, elapsed_ms: float) -> None:
        """Record a pre-computed timing (e.g. from an external source)."""
        self.timings[phase] = elapsed_ms

    @contextmanager
    def phase(self, name: str) -> Generator[None, None, None]:
        """Context manager for timing a phase.

        Usage:
            with timer.phase("dossier_parse"):
                result = parse_dossier(raw)
        """
        self.start(name)
        try:
            yield
        finally:
            self.stop()

    def to_dict(self) -> Dict[str, float]:
        """Return timings as a dict (phase_name -> elapsed_ms)."""
        return dict(self.timings)

    def to_log_str(self) -> str:
        """Format timings as a compact log string."""
        parts = []
        for phase, ms in self.timings.items():
            parts.append(f"{phase}={ms:.1f}ms")
        return " | ".join(parts)

    def to_summary_table(self, title: Optional[str] = None) -> str:
        """Format timings as a markdown table for documentation.

        Groups sub-phases under their parent with indentation.
        """
        lines = []
        if title:
            lines.append(f"### {title}")
            lines.append("")

        lines.append("| Phase | Time (ms) |")
        lines.append("|-------|-----------|")

        # Group by parent phase
        parents: Dict[str, List[Tuple[str, float]]] = {}
        top_level: List[Tuple[str, float]] = []

        for phase, ms in self.timings.items():
            if "." in phase:
                parent = phase.rsplit(".", 1)[0]
                if parent not in parents:
                    parents[parent] = []
                parents[parent].append((phase, ms))
            else:
                top_level.append((phase, ms))

        for phase, ms in top_level:
            lines.append(f"| **{phase}** | **{ms:.2f}** |")
            if phase in parents:
                for sub_phase, sub_ms in parents[phase]:
                    sub_name = sub_phase.rsplit(".", 1)[1]
                    lines.append(f"| &nbsp;&nbsp;{sub_name} | {sub_ms:.2f} |")

        return "\n".join(lines)
