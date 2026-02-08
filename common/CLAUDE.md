# VVP Common Library

## What This Package Does
Shared code installed as a package (`pip install -e common/`). Used by verifier, issuer, and SIP redirect services. Provides models, serialization, schema infrastructure, and utilities.

## Package Structure

```
common/
├── vvp/
│   ├── core/
│   │   ├── logging.py          # configure_logging() - structured JSON logging
│   │   └── exceptions.py       # Base exception classes
│   ├── models/
│   │   ├── acdc.py             # ACDC data model (shared between services)
│   │   └── dossier.py          # Dossier data models
│   ├── canonical/
│   │   ├── keri_canonical.py   # KERI canonical JSON serialization (field ordering)
│   │   ├── cesr.py             # CESR encoding/decoding utilities
│   │   ├── parser.py           # CESR stream parser
│   │   └── said.py             # SAID computation (Blake3-256)
│   ├── schema/
│   │   ├── registry.py         # Schema SAID → type mapping and lookup
│   │   ├── store.py            # Schema storage (file-based)
│   │   └── validator.py        # JSON Schema validation of ACDC attributes
│   ├── sip/
│   │   └── models.py           # SIPRequest model (shared by SIP services)
│   └── utils/
│       └── tn_utils.py         # Telephone number normalization (E.164)
└── pyproject.toml              # Package definition
```

## Key Algorithms

### SAID Computation (`canonical/said.py`)
1. Replace `d` field with placeholder string of correct length
2. Serialize to canonical form (ordered JSON, no extra whitespace)
3. Hash with Blake3-256
4. Encode as CESR-compatible Base64 string
5. Result is the SAID for the `d` field

### KERI Canonical Serialization (`canonical/keri_canonical.py`)
KERI requires specific JSON field ordering for deterministic serialization:
- Version string fields first
- Then `d` (SAID), `i` (issuer), `s` (schema)
- Then remaining fields in spec-defined order
- No extra whitespace, UTF-8 encoding

### CESR Parsing (`canonical/cesr.py`, `parser.py`)
- Count code parsing: 2-byte hard code + variable soft code → count
- Signature extraction: indexed signatures mapped to preceding events
- Forward compatibility: unknown codes skip gracefully

## Schema Registry (`schema/registry.py`)
Maps schema SAIDs to credential types and provides lookup:
- `get_credential_type(schema_said)` → "LE", "QVI", "APE", "DE", "TNAlloc", etc.
- `validate_schema(data, schema_said)` → validates attributes against JSON Schema
- Registry is additive - new schemas added without removing existing ones

## SIP Model (`sip/models.py`)
Shared `SIPRequest` model used by SIP redirect and SIP verify services:
- Parsed SIP headers (From, To, Via, Call-ID, CSeq)
- Extracted phone numbers (E.164)
- VVP-specific headers (Identity, VVP-Identity, X-VVP-API-Key)

## Usage
```python
from common.vvp.core.logging import configure_logging
from common.vvp.canonical.said import compute_said
from common.vvp.schema.registry import get_credential_type
from common.vvp.sip.models import SIPRequest
from common.vvp.utils.tn_utils import normalize_e164
```
