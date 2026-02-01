## Code Review: Username/Password Auth - Fixes

**Verdict:** APPROVED

### Fix Assessment
Both requested changes are in place. The default admin user is now disabled by default with an explicit comment in `services/issuer/config/users.json`, reducing the production footgun. Session revocation checks now refresh user and API key state via `reload_if_stale()` before evaluating enablement/revocation, which addresses the stale-state risk in `services/issuer/app/auth/session.py`.

### Findings
- No remaining issues.

### Required Changes (if not APPROVED)
N/A
