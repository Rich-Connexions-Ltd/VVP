Code Review: Phase 9.4 - TEL Resolution Architecture Fix
Verdict: APPROVED

Implementation Assessment
Inline TEL parsing, registry OOBI derivation, and fallback chain are implemented as planned. `revocation_clear` uses inline TEL first, then registry OOBI, then default witnesses. Evidence formatting and summary counts are present.

Code Quality
Changes are clear and well‑logged. Helper `_query_registry_tel()` isolates the registry OOBI logic and keeps the main flow readable. Latin‑1 decoding is documented and applied consistently.

Test Coverage
Added tests cover inline TEL success, registry OOBI derivation, fallback behavior, and binary‑safe parsing. Coverage looks adequate for the new paths.

Findings
[Low]: Evidence tags for UNKNOWN/ERROR don’t include `revocation_source`, which can make debugging mixed results harder; consider adding a source tag even on indeterminate outcomes. `app/vvp/verify.py:197`
