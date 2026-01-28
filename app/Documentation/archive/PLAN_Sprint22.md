# Sprint 22: Credential Card & Chain Graph Enhancements

## Problem Statement

The current credential card UI has limitations that hide important credential data:
1. **Attributes are collapsed** - Only 3 secondary attributes shown, nested objects display as "(complex)", arrays truncated to 2 items
2. **Edge links not navigable** - Links use HTMX to append cards below, but can't navigate to or highlight linked credentials
3. **No visual chain graph** - Credential layers are rendered as cards without visual connectors showing the trust relationships

## User Requirements

1. Display all attributes prominently (not in collapsed section), with proper handling for:
   - Simple values: `"role": "Tn Allocator"`
   - Booleans: `"doNotOriginate": false`
   - Dates: `"startDate": "2024-11-25T20:20:39+00:00"`
   - Nested objects: `"numbers": {"rangeStart": "+447884666200", "rangeEnd": "+447884666200"}`
   - Arrays: `"c_goal": ["ops.it.telco.send.sign"]`

2. Make edge links clickable to navigate to the linked credential

3. Display a graphical credential chain graph with visual links between credentials

## Spec References

- §6.1: Dossier structure and credential chain
- §5.1-7: Trust chain validation to root of trust
- Sprint 21 Plan: Credential card view-model architecture

## Implementation Summary

### Part 1: Collapsible Attribute Sections

Grouped attributes by category in collapsible sections:
- **Identity**: LEI, legalName, role, issuee
- **Dates & Times**: startDate, endDate, dt, issuanceDate (formatted human-readable)
- **Permissions**: c_goal, channel, doNotOriginate (Yes/No for booleans)
- **Numbers & Ranges**: tn, numbers.rangeStart/rangeEnd (flattened nested objects)
- **Other**: Any remaining attributes

### Part 2: Clickable Edge Links

Edge links now scroll and highlight target credential:
- `id="cred-{said}"` added to each credential card
- `highlightCredential(said)` JavaScript function scrolls and pulse-highlights
- 2-second highlight animation with box-shadow

### Part 3: Visual Chain Graph (SVG Connectors)

SVG connectors between credential cards showing trust relationships:
- Bezier curves from parent card bottom to child card top
- Color-coded by edge type:
  - vetting → green (#28a745)
  - delegation → blue (#007bff)
  - issued_by → purple (#6f42c1)
  - jl (jurisdiction) → orange (#fd7e14)
- Arrow markers at endpoints
- Redraw on window resize and details toggle
- Hidden on mobile (< 768px)

### Part 4: Field Tooltips

Normative descriptions from ToIP ACDC specification on mouseover:
- Core ACDC fields (v, d, i, s, a, e, r, n, dt)
- Common attribute fields (LEI, legalName, tn, channel)
- `.has-tooltip` CSS class with dotted underline

### Part 5: Raw Contents Section

Collapsed "Raw Contents" section with all ACDC fields:
- Complete list of all fields with tooltips
- Recursively flattened nested dicts with dot notation
- Formatted values (arrays, booleans, dates)

### Part 6: Redaction Masking

ACDC partial disclosure placeholders properly displayed:
- `"_"` full redaction placeholder → "(redacted)"
- `"_:type"` typed placeholders → "(redacted)"
- `""`, `"#"`, `"[REDACTED]"` → "(redacted)"
- `.attr-redacted` CSS class with muted styling

### Part 7: Inline Revocation Display

Revocation status displayed inline (not lazy-loaded):
- ACTIVE → green badge
- REVOKED → red badge
- UNKNOWN → yellow badge with error tooltip

## Files Changed

| File | Summary |
|------|---------|
| `app/vvp/ui/credential_viewmodel.py` | Added AttributeSection, formatting functions, sections field, tooltips, raw_contents, redaction detection |
| `app/vvp/ui/__init__.py` | Export AttributeSection |
| `app/templates/partials/credential_card.html` | Collapsible sections, edge links, tooltips, Raw Contents, inline revocation |
| `app/templates/partials/credential_graph.html` | SVG container, edges data attribute |
| `app/templates/base.html` | CSS for sections/connectors/tooltips/highlight/redaction, JS functions |
| `tests/test_credential_viewmodel.py` | 66 new tests for Sprint 22 features |
| `scripts/run-tests.sh` | Test runner script with DYLD_LIBRARY_PATH |

## Test Results

```
999 passed, 20 warnings in 5.63s
```

## Review History

- **Rev 0**: CHANGES_REQUESTED - Redaction masking not applied to `_build_attribute_sections`
- **Rev 1**: APPROVED - Added `_is_redacted_value()` and updated `_format_value()`
