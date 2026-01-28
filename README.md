# VVP Verifier

![Status](https://img.shields.io/badge/status-active-success.svg) ![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)

The **VVP Verifier** is a reference implementation for verifying calls under the **Verifiable Voice Protocol (VVP)**. It enables cryptographically verifiable assertions about the legitimacy and authority of a call originator, intended to complement STIR/SHAKEN with richer, machine-verifiable claims.

## Objectives

- **Proof of Rights**: Verify not just identity, but the rights to use specific numbers or resources.
- **Multi-Claim Assertions**: Support validation of brand affiliation, call purpose, and other complex claims.
- **End-to-End Verification**: Enable verification without reliance on central certificate authorities using decentralized identity standards.

## Key Concepts

- **VVP (Verifiable Voice Protocol)**: A mechanism for conveying verifiable assertions alongside real-time voice communications.
- **KERI (Key Event Receipt Infrastructure)**: A decentralized key management system using Key Event Logs (KELs) for tracking identifier state without a central PKI.
- **ACDC (Authentic Chained Data Containers)**: Structured, verifiable data objects for expressing chained claims and credentials.

> For a deep dive into the protocol and architecture, see the [VVP Verifier Documentation](app/Documentation/VVP_Verifier_Documentation.md).

## Getting Started

### Prerequisites

- **Python 3.12** or higher
- **libsodium** (Required for cryptographic operations)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/andrewbalercnx/vvp-verifier.git
    cd vvp-verifier
    ```

2.  **Install dependencies:**
    It is recommended to use a virtual environment.
    ```bash
    pip install -r requirements.txt
    # OR if using uv/poetry, follow their respective install instructions
    pip install ".[test]" # To include test dependencies
    ```

3.  **Verify libsodium installation:**
    Ensure `libsodium` is installed and accessible.
    *macOS (Homebrew):*
    ```bash
    brew install libsodium
    ```

## Usage

### Running the Server

Start the development server using `uvicorn`:

```bash
uvicorn app.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

### API Documentation

Once the server is running, interactive API documentation is available at:
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

## Testing

This project uses `pytest` for testing. A helper script is provided to manage library paths (specifically for libsodium).

**Run all tests:**
```bash
./scripts/run-tests.sh
```

**Run specific tests:**
```bash
./scripts/run-tests.sh tests/test_signature.py
```

**Run with coverage:**
```bash
./scripts/run-tests.sh --cov=app --cov-report=term-missing
```

## Project Structure

```
app/
├── core/           # Configuration and core utilities
├── vvp/            # Core VVP logic
│   ├── keri/       # KERI integration (KELs, CESR, Signatures)
│   ├── acdc/       # ACDC credential handling
│   ├── dossier/    # Dossier fetching and validation
│   └── verify/     # Main verification engine
├── main.py         # FastAPI application entry point
└── Documentation/  # Detailed project documentation
tests/              # Test suite
scripts/            # Helper scripts (e.g., test runner)
```

## Documentation

- [VVP Verifier Documentation](app/Documentation/VVP_Verifier_Documentation.md): Comprehensive guide to objectives, background, and architecture.
- [Specification](app/Documentation/VVP_Verifier_Specification_v1.5.md): Detailed VVP specification.
- [Implementation Checklist](app/Documentation/VVP_Implementation_Checklist.md): Tracking implementation progress.
