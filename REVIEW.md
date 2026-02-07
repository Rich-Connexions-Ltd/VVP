## Code Re-Review: Sprint 48 - Revision 2

**Verdict:** APPROVED

### Changes Assessment
The polling status gating now preserves WebSocket status and only shows polling/error while in polling mode. The idle timeout logic is correctly tied to client messages only, with a remaining-time calculation and timeout recheck, so server-to-client queue activity no longer masks inactivity. Both prior issues are adequately fixed.

### Findings
- None.
