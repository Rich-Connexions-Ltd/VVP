#!/bin/bash
# Run VVP integration tests against specified environment
#
# Usage:
#   ./scripts/run-integration-tests.sh [--local|--docker|--azure] [--suite SUITE] [pytest args...]
#
# Suites:
#   all      - All integration tests (default)
#   issuer   - Only issuer-API tests (no verifier calls)
#   e2e      - Only tests that exercise both issuer and verifier
#
# Examples:
#   ./scripts/run-integration-tests.sh --local                    # Run all against local stack
#   ./scripts/run-integration-tests.sh --local --suite issuer     # Issuer-only tests
#   ./scripts/run-integration-tests.sh --local --suite e2e        # E2E tests only
#   ./scripts/run-integration-tests.sh --azure --suite all        # All tests against Azure
#   ./scripts/run-integration-tests.sh --local -v                 # Run with verbose output
#   ./scripts/run-integration-tests.sh --local -k lifecycle       # Run specific tests

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Parse mode and suite arguments
MODE="local"
SUITE="all"
PYTEST_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)
            MODE="local"
            shift
            ;;
        --docker)
            MODE="docker"
            shift
            ;;
        --azure)
            MODE="azure"
            shift
            ;;
        --suite)
            SUITE="$2"
            shift 2
            ;;
        *)
            PYTEST_ARGS+=("$1")
            shift
            ;;
    esac
done

export VVP_TEST_MODE="$MODE"

# Set library paths for libsodium
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:/usr/local/lib:$DYLD_LIBRARY_PATH"
export LD_LIBRARY_PATH="/usr/lib:/usr/local/lib:$LD_LIBRARY_PATH"

# Set default URLs based on mode
if [ "$MODE" = "local" ]; then
    export VVP_ISSUER_URL="${VVP_ISSUER_URL:-http://localhost:8001}"
    export VVP_VERIFIER_URL="${VVP_VERIFIER_URL:-http://localhost:8000}"
elif [ "$MODE" = "docker" ]; then
    export VVP_ISSUER_URL="${VVP_ISSUER_URL:-http://localhost:8001}"
    export VVP_VERIFIER_URL="${VVP_VERIFIER_URL:-http://localhost:8000}"
elif [ "$MODE" = "azure" ]; then
    # Default to production Azure FQDNs
    export VVP_ISSUER_URL="${VVP_ISSUER_URL:-https://vvp-issuer.rcnx.io}"
    export VVP_VERIFIER_URL="${VVP_VERIFIER_URL:-https://vvp-verifier.rcnx.io}"
fi

# Build marker expression based on mode and suite
case "$SUITE" in
    all)
        if [ "$MODE" = "azure" ]; then
            MARKERS="integration and not benchmark"
        else
            MARKERS="integration and not azure and not benchmark"
        fi
        ;;
    issuer)
        if [ "$MODE" = "azure" ]; then
            MARKERS="integration and issuer and not benchmark"
        else
            MARKERS="integration and issuer and not azure and not benchmark"
        fi
        ;;
    e2e)
        if [ "$MODE" = "azure" ]; then
            MARKERS="integration and e2e and not benchmark"
        else
            MARKERS="integration and e2e and not azure and not benchmark"
        fi
        ;;
    *)
        echo "Error: Unknown suite '$SUITE'. Use: all, issuer, or e2e"
        exit 1
        ;;
esac

echo "=============================================="
echo "VVP Integration Tests"
echo "=============================================="
echo "Mode:    $MODE"
echo "Suite:   $SUITE"
echo "Issuer:  $VVP_ISSUER_URL"
echo "Verifier: $VVP_VERIFIER_URL"
echo "Markers: $MARKERS"
echo "=============================================="

# Check if services are running
echo "Checking service availability..."

if ! curl -s --max-time 5 "$VVP_ISSUER_URL/healthz" > /dev/null 2>&1; then
    echo "Warning: Issuer service not responding at $VVP_ISSUER_URL/healthz"
    if [ "$MODE" = "local" ]; then
        echo "Start the issuer with: ./scripts/restart-issuer.sh"
    fi
fi

if [ "$SUITE" != "issuer" ]; then
    if ! curl -s --max-time 5 "$VVP_VERIFIER_URL/healthz" > /dev/null 2>&1; then
        echo "Warning: Verifier service not responding at $VVP_VERIFIER_URL/healthz"
        if [ "$MODE" = "local" ]; then
            echo "Start the verifier with: ./scripts/restart-server.sh"
        fi
    fi
fi

# Create benchmark output directory
export VVP_BENCHMARK_OUTPUT_DIR="$REPO_ROOT/tests/integration/benchmarks/output"
mkdir -p "$VVP_BENCHMARK_OUTPUT_DIR"

# Run tests
cd "$REPO_ROOT"
python -m pytest tests/integration/ \
    -v \
    --tb=short \
    -m "$MARKERS" \
    "${PYTEST_ARGS[@]}"

# Copy benchmark results if they exist
if [ -f "$VVP_BENCHMARK_OUTPUT_DIR/benchmark_results.json" ]; then
    echo ""
    echo "Benchmark results saved to: $VVP_BENCHMARK_OUTPUT_DIR/benchmark_results.json"
fi
