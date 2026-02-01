#!/bin/bash
# Run VVP integration tests against specified environment
#
# Usage:
#   ./scripts/run-integration-tests.sh [--local|--docker|--azure] [pytest args...]
#
# Examples:
#   ./scripts/run-integration-tests.sh --local              # Run against local stack
#   ./scripts/run-integration-tests.sh --docker             # Run against docker-compose
#   ./scripts/run-integration-tests.sh --azure              # Run against Azure deployment
#   ./scripts/run-integration-tests.sh --local -v           # Run with verbose output
#   ./scripts/run-integration-tests.sh --local -k lifecycle # Run specific tests

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Parse mode argument
MODE="local"
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

# Select markers based on mode
if [ "$MODE" = "azure" ]; then
    MARKERS="-m integration"  # Run all including azure
else
    MARKERS="-m integration and not azure"  # Skip azure-only tests
fi

echo "=============================================="
echo "VVP Integration Tests"
echo "=============================================="
echo "Mode: $MODE"
echo "Issuer URL: $VVP_ISSUER_URL"
echo "Verifier URL: $VVP_VERIFIER_URL"
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

if ! curl -s --max-time 5 "$VVP_VERIFIER_URL/healthz" > /dev/null 2>&1; then
    echo "Warning: Verifier service not responding at $VVP_VERIFIER_URL/healthz"
    if [ "$MODE" = "local" ]; then
        echo "Start the verifier with: ./scripts/restart-server.sh"
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
    $MARKERS \
    "${PYTEST_ARGS[@]}"

# Copy benchmark results if they exist
if [ -f "$VVP_BENCHMARK_OUTPUT_DIR/benchmark_results.json" ]; then
    echo ""
    echo "Benchmark results saved to: $VVP_BENCHMARK_OUTPUT_DIR/benchmark_results.json"
fi
