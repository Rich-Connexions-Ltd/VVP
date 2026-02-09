"""Performance characterization tests for dossier parsing pipeline.

Tests dossier parsing stages 1-4 with existing fixtures. Timing aligns
with the 5 stages defined in knowledge/dossier-parsing-algorithm.md:

    Stage 1: Format Detection
    Stage 2: CESR Stream Parsing
    Stage 3: ACDC Extraction and Filtering
    Stage 4: DAG Construction and Structural Validation
    Stage 5: Credential Integrity and Chain Validation (offline portion)

Fixtures:
    PERF-E1: trial_dossier.json  (Provenant wrapper, CESR, 7 ACDCs, 5 schemas)
    PERF-E2: acme_dossier.json   (plain JSON, 3 ACDCs, linear chain)
    PERF-S1: Synthetic 20-ACDC chain (generated at runtime)

Run with:
    ./scripts/run-tests.sh tests/perf/test_dossier_perf.py -v -s
"""

import json
import statistics
import time
from pathlib import Path

import pytest

from app.vvp.dossier.parser import _is_cesr_stream, parse_dossier
from app.vvp.dossier.validator import build_dag, validate_dag
from app.vvp.timing import PhaseTimer

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------
_VERIFIER_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_SIP_FIXTURES = Path(__file__).resolve().parents[3] / "sip-redirect" / "tests" / "fixtures"


def _load_fixture(name: str) -> bytes:
    """Load a test fixture file as raw bytes."""
    for base in (_VERIFIER_FIXTURES, _SIP_FIXTURES):
        path = base / name
        if path.exists():
            return path.read_bytes()
    raise FileNotFoundError(f"Fixture {name} not found in {_VERIFIER_FIXTURES} or {_SIP_FIXTURES}")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _time_dossier_stages(raw: bytes) -> PhaseTimer:
    """Run all offline dossier parsing stages with timing."""
    timer = PhaseTimer()

    # Stage 1: Format Detection
    with timer.phase("stage1_format_detect"):
        is_cesr = _is_cesr_stream(raw)

    # Stages 1-3 combined: parse_dossier() performs format detection,
    # CESR/JSON parsing, and ACDC extraction in one call.
    with timer.phase("stages1_3_parse_dossier"):
        nodes, signatures = parse_dossier(raw)

    # Stage 4a: DAG construction
    with timer.phase("stage4a_dag_build"):
        dag = build_dag(nodes)

    # Stage 4b-e: DAG validation (cycles, root, ToIP warnings)
    with timer.phase("stage4b_dag_validate"):
        validate_dag(dag, allow_aggregate=True)

    # Stage 5a: SAID verification (offline, no network)
    with timer.phase("stage5a_said_verify"):
        try:
            from app.vvp.acdc.parser import validate_acdc_said
            for node in nodes:
                try:
                    validate_acdc_said(node.raw)
                except Exception:
                    pass  # Expected for test fixtures with synthetic SAIDs
        except ImportError:
            pass  # blake3/pysodium not available

    # Record metadata
    timer.record("_meta.nodes", float(len(nodes)))
    timer.record("_meta.signatures", float(len(signatures)))
    timer.record("_meta.bytes", float(len(raw)))

    return timer


def _build_synthetic_chain(n_credentials: int) -> bytes:
    """Build a synthetic JSON dossier with n_credentials in a linear chain."""
    acdcs = []

    # Root credential (no edges)
    root_said = "E" + "R" * 43
    acdcs.append({
        "d": root_said,
        "i": "E" + "I" * 43,
        "s": "E" + "S" * 43,
        "a": {"d": "E" + "A" * 43, "LEI": "549300SYNTH0000001"},
        "e": {},
    })

    # Chain of additional credentials, each pointing to its parent
    prev_said = root_said
    for i in range(n_credentials - 1):
        said = f"E{i:03d}" + "C" * 40
        acdcs.append({
            "d": said,
            "i": "E" + "I" * 43,
            "s": "E" + "S" * 43,
            "a": {"d": f"EA{i:03d}" + "T" * 39, "name": f"Credential-{i}"},
            "e": {"d": f"EE{i:03d}" + "G" * 39, "parent": {"n": prev_said}},
        })
        prev_said = said

    return json.dumps(acdcs).encode("utf-8")


# ===========================================================================
# Test classes
# ===========================================================================


class TestDossierParsingStageTiming:
    """Time each dossier parsing stage for existing fixtures.

    Corresponds to the 5 stages in knowledge/dossier-parsing-algorithm.md.
    """

    @pytest.fixture
    def trial_dossier_bytes(self) -> bytes:
        return _load_fixture("trial_dossier.json")

    @pytest.fixture
    def acme_dossier_bytes(self) -> bytes:
        return _load_fixture("acme_dossier.json")

    def test_perf_e1_trial_dossier(self, trial_dossier_bytes):
        """PERF-E1: trial_dossier.json (Provenant wrapper, 7 ACDCs)."""
        timer = _time_dossier_stages(trial_dossier_bytes)

        print(f"\n{'=' * 65}")
        print(f"PERF-E1: trial_dossier.json ({len(trial_dossier_bytes):,} bytes)")
        print(f"{'=' * 65}")
        print(timer.to_log_str())
        print()
        print(timer.to_summary_table(title="PERF-E1: Trial Dossier"))

        # Correctness assertions
        assert timer.timings["_meta.nodes"] >= 5
        assert timer.timings["_meta.bytes"] == len(trial_dossier_bytes)

    def test_perf_e2_acme_dossier(self, acme_dossier_bytes):
        """PERF-E2: acme_dossier.json (plain JSON, 3 ACDCs, linear)."""
        timer = _time_dossier_stages(acme_dossier_bytes)

        print(f"\n{'=' * 65}")
        print(f"PERF-E2: acme_dossier.json ({len(acme_dossier_bytes):,} bytes)")
        print(f"{'=' * 65}")
        print(timer.to_log_str())
        print()
        print(timer.to_summary_table(title="PERF-E2: Acme Dossier"))

        # Correctness assertions
        assert timer.timings["_meta.nodes"] == 3
        assert timer.timings["_meta.bytes"] == len(acme_dossier_bytes)

    def test_perf_s1_synthetic_20_chain(self):
        """PERF-S1: Synthetic 20-ACDC linear chain."""
        raw = _build_synthetic_chain(20)
        timer = _time_dossier_stages(raw)

        print(f"\n{'=' * 65}")
        print(f"PERF-S1: Synthetic 20-ACDC chain ({len(raw):,} bytes)")
        print(f"{'=' * 65}")
        print(timer.to_log_str())
        print()
        print(timer.to_summary_table(title="PERF-S1: Synthetic 20-chain"))

        assert timer.timings["_meta.nodes"] == 20

    def test_perf_s2_synthetic_50_chain(self):
        """PERF-S2: Synthetic 50-ACDC linear chain (stress test)."""
        raw = _build_synthetic_chain(50)
        timer = _time_dossier_stages(raw)

        print(f"\n{'=' * 65}")
        print(f"PERF-S2: Synthetic 50-ACDC chain ({len(raw):,} bytes)")
        print(f"{'=' * 65}")
        print(timer.to_log_str())
        print()
        print(timer.to_summary_table(title="PERF-S2: Synthetic 50-chain"))

        assert timer.timings["_meta.nodes"] == 50


class TestParsingVarianceMeasurement:
    """Measure variance across multiple iterations for stable baselines."""

    N_ITERATIONS = 20

    @pytest.fixture
    def trial_dossier_bytes(self) -> bytes:
        return _load_fixture("trial_dossier.json")

    @pytest.fixture
    def acme_dossier_bytes(self) -> bytes:
        return _load_fixture("acme_dossier.json")

    def _run_n_iterations(self, raw: bytes, n: int):
        """Run dossier parsing n times, return per-stage timing lists."""
        stage_times = {
            "parse_dossier": [],
            "dag_build": [],
            "dag_validate": [],
        }

        for _ in range(n):
            t0 = time.perf_counter()
            nodes, sigs = parse_dossier(raw)
            t1 = time.perf_counter()
            dag = build_dag(nodes)
            t2 = time.perf_counter()
            validate_dag(dag, allow_aggregate=True)
            t3 = time.perf_counter()

            stage_times["parse_dossier"].append((t1 - t0) * 1000)
            stage_times["dag_build"].append((t2 - t1) * 1000)
            stage_times["dag_validate"].append((t3 - t2) * 1000)

        return stage_times

    def _print_stats(self, label: str, times: list):
        avg = statistics.mean(times)
        med = statistics.median(times)
        mn = min(times)
        mx = max(times)
        sd = statistics.stdev(times) if len(times) > 1 else 0
        print(f"  {label:20s}: avg={avg:.3f}ms  med={med:.3f}ms  "
              f"min={mn:.3f}ms  max={mx:.3f}ms  sd={sd:.3f}ms")

    def test_trial_dossier_variance(self, trial_dossier_bytes):
        """Measure iteration-to-iteration variance for trial_dossier."""
        n = self.N_ITERATIONS
        stage_times = self._run_n_iterations(trial_dossier_bytes, n)

        print(f"\n{'=' * 65}")
        print(f"Variance: trial_dossier.json ({n} iterations)")
        print(f"{'=' * 65}")
        for stage, times in stage_times.items():
            self._print_stats(stage, times)

        # Stability: max should be <20x min (allows JIT/cache warmup)
        parse_t = stage_times["parse_dossier"]
        if min(parse_t) > 0:
            ratio = max(parse_t) / min(parse_t)
            assert ratio < 20, f"Parse variance too high: ratio={ratio:.1f}"

    def test_acme_dossier_variance(self, acme_dossier_bytes):
        """Measure iteration-to-iteration variance for acme_dossier."""
        n = self.N_ITERATIONS
        stage_times = self._run_n_iterations(acme_dossier_bytes, n)

        print(f"\n{'=' * 65}")
        print(f"Variance: acme_dossier.json ({n} iterations)")
        print(f"{'=' * 65}")
        for stage, times in stage_times.items():
            self._print_stats(stage, times)


class TestFormatDetectionMicrobenchmark:
    """Microbenchmark for _is_cesr_stream() format detection heuristics."""

    N_CALLS = 5000

    @pytest.fixture
    def trial_dossier_bytes(self) -> bytes:
        return _load_fixture("trial_dossier.json")

    def test_provenant_wrapper_detection(self, trial_dossier_bytes):
        """Format detection for Provenant JSON wrapper format."""
        n = self.N_CALLS
        t0 = time.perf_counter()
        for _ in range(n):
            _is_cesr_stream(trial_dossier_bytes)
        elapsed = (time.perf_counter() - t0) * 1000

        print(f"\n_is_cesr_stream(provenant) x {n}: "
              f"{elapsed:.2f}ms total, {elapsed / n:.4f}ms/call")

    def test_plain_json_array_detection(self):
        """Format detection for plain JSON array."""
        raw = json.dumps([{
            "d": "E" + "X" * 43,
            "i": "E" + "Y" * 43,
            "s": "E" + "Z" * 43,
        }]).encode("utf-8")

        n = self.N_CALLS
        t0 = time.perf_counter()
        for _ in range(n):
            _is_cesr_stream(raw)
        elapsed = (time.perf_counter() - t0) * 1000

        print(f"\n_is_cesr_stream(plain JSON) x {n}: "
              f"{elapsed:.2f}ms total, {elapsed / n:.4f}ms/call")

    def test_cesr_prefix_detection(self):
        """Format detection for CESR version marker prefix."""
        raw = b'-_AAA{"d":"EXXXXXXXXX"}' + b"0" * 2000

        n = self.N_CALLS
        t0 = time.perf_counter()
        for _ in range(n):
            _is_cesr_stream(raw)
        elapsed = (time.perf_counter() - t0) * 1000

        print(f"\n_is_cesr_stream(CESR prefix) x {n}: "
              f"{elapsed:.2f}ms total, {elapsed / n:.4f}ms/call")


class TestScalingSweep:
    """Measure how parsing time scales with dossier size."""

    SIZES = [3, 5, 10, 20, 50, 100]

    def test_scaling_by_credential_count(self):
        """Time parse_dossier + build_dag for increasing chain lengths."""
        results = []

        for n in self.SIZES:
            raw = _build_synthetic_chain(n)

            # Warmup
            parse_dossier(raw)

            # Timed run (average of 5)
            parse_times = []
            dag_times = []
            for _ in range(5):
                t0 = time.perf_counter()
                nodes, _ = parse_dossier(raw)
                t1 = time.perf_counter()
                dag = build_dag(nodes)
                validate_dag(dag, allow_aggregate=True)
                t2 = time.perf_counter()
                parse_times.append((t1 - t0) * 1000)
                dag_times.append((t2 - t1) * 1000)

            avg_parse = statistics.mean(parse_times)
            avg_dag = statistics.mean(dag_times)
            results.append((n, len(raw), avg_parse, avg_dag))

        print(f"\n{'=' * 65}")
        print("Scaling sweep: parse_dossier + dag_build by credential count")
        print(f"{'=' * 65}")
        print(f"{'N':>5s} | {'Bytes':>8s} | {'Parse (ms)':>11s} | {'DAG (ms)':>9s} | {'Total (ms)':>11s}")
        print(f"{'-' * 5}-+-{'-' * 8}-+-{'-' * 11}-+-{'-' * 9}-+-{'-' * 11}")
        for n, nbytes, parse_ms, dag_ms in results:
            total = parse_ms + dag_ms
            print(f"{n:5d} | {nbytes:8,d} | {parse_ms:11.3f} | {dag_ms:9.3f} | {total:11.3f}")

        # Sanity: 100 credentials should parse in under 1 second
        last_total = results[-1][2] + results[-1][3]
        assert last_total < 1000, f"100-credential chain took {last_total:.1f}ms (>1s)"
