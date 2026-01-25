# Developer Guide

Welcome to the VVP Verifier project. This guide covers environment setup, project structure, and testing workflows for developers.

## 1. Environment Setup

### Prerequisites
- Python 3.10+
- `pip`
- `git`

### Installation
1. Clone the repository.
2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: This project vendors specific KERI libraries in `app/vvp/keri/` to ensure stability.*

## 2. Project Structure

The codebase is organized by domain logic rather than framework layers.

```text
app/
├── core/               # Application configuration and constants
│   └── config.py       # Normative constants linked to VVP Specs
├── vvp/                # Main Protocol Logic
│   ├── header.py       # VVP-Identity header parsing
│   ├── passport.py     # PASSporT JWT validation
│   ├── verify.py       # Orchestration logic
│   └── keri/           # Cryptographic Infrastructure
│       ├── cesr.py     # Stream parsing (CESR format)
│       ├── kel_*.py    # Key Event Log resolution
│       └── cache.py    # Key state caching
└── Documentation/      # Specifications and Plans
```

## 3. Testing Strategy

We use `pytest` for all testing. Tests are categorized by "Tiers" corresponding to the implementation roadmap.

### Running Tests

**Run all tests:**
```bash
pytest
```

**Run specific tiers:**
Tests are not strictly marked, but follow the folder structure or naming conventions.

- **Tier 1 (Basic Syntax/Crypto):**
  ```bash
  pytest tests/test_header.py tests/test_passport.py
  ```

- **Tier 2 (KERI/KEL Resolution):**
  ```bash
  pytest tests/test_kel_*.py tests/test_cesr_parser.py
  ```

### Test Vectors
The `tests/vectors/` directory contains normative test vectors derived from the VVP specification. These ensure interoperability.

## 4. Development Workflow

We use an AI-assisted pair programming workflow defined in `CLAUDE.md`.

1.  **Plan**: Before writing code, update `PLAN.md` with the design.
2.  **Review**: Use the "Reviewer" persona to approve the plan.
3.  **Implement**: Write code and tests.
4.  **Verify**: Run tests and update `CHANGES.md`.
5.  **Archive**: Move the plan to `app/Documentation/archive/`.

## 5. Coding Standards

- **Type Hinting**: All function signatures must be typed.
- **Docstrings**: Use Google-style docstrings.
- **Spec Traceability**: When implementing normative logic, add a comment referencing the specific spec section (e.g., `# Per VVP §5.2A`).