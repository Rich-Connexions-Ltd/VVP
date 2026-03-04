/**
 * VVP Display Module for PWA SIP Client
 *
 * Extracts VVP verification data from SIP.js 0.15.x session headers
 * and provides status/badge configuration for the call overlay UI.
 *
 * SIP Headers (set by FreeSWITCH dialplan after verification):
 *   X-VVP-Brand-Name    - Verified caller brand name
 *   X-VVP-Brand-Logo    - URL to brand logo
 *   X-VVP-Status        - Overall verification result (see statusConfig below)
 *   X-VVP-Vetter-Status - Vetter geographic constraint result (see vetterStatusConfig below)
 *
 * ── X-VVP-Status: possible values ──────────────────────────────────────────
 *
 *  VALID         ✓ Verified
 *    All checks passed: PASSporT cryptographically valid (signature OK, iat within
 *    5 s drift, not expired), credential chain verified against trusted root AIDs,
 *    all credentials unrevoked, TN rights confirmed (TNAlloc covers calling TN).
 *
 *  INVALID       ✗ Not Verified
 *    A hard, non-recoverable failure:
 *    - PASSporT signature invalid or tampered
 *    - iat drift > 5 s (clock skew too large)
 *    - PASSporT expired
 *    - orig.tn in PASSporT does not match calling party TN
 *    - One or more credentials in the chain are revoked
 *    - Credential chain broken (issuer AID mismatch)
 *    - Dossier integrity check failed (SAID mismatch)
 *    Call still delivered; callee should treat caller identity as unverified.
 *
 *  INDETERMINATE ? Pending
 *    A transient or recoverable failure — verification could not be completed:
 *    - OOBI for issuer AID not yet published to witnesses (HTTP 404);
 *      fix: POST /admin/publish-identity/{name} on the Issuer
 *    - Witness unreachable or slow (network timeout)
 *    - Dossier URL temporarily unavailable (Issuer down)
 *    - TEL revocation check inconclusive (witness returned error)
 *    - PASSporT missing or malformed but other checks passed
 *    May resolve automatically on retry. Treat as unverified for this call.
 *
 *  UNKNOWN       — Unknown
 *    No X-VVP-Status header present in the INVITE. Occurs when:
 *    - Call did not go through the VVP signing/verification flow
 *    - Verification service crashed before setting response headers
 *    - Call came from an unregistered or bypass route
 *
 * ── X-VVP-Vetter-Status: possible values ───────────────────────────────────
 *
 *  PASS                  Vetter: Authorized
 *    VetterCertification found for all credentials (via "certification" edge).
 *    All ECC (country calling code) and jurisdiction (ISO 3166) targets match.
 *    The issuing vetter is authorised to issue in this geographic region.
 *
 *  FAIL-ECC              Vetter: ECC Violation
 *    VetterCert found, but the calling TN's E.164 country code is NOT in the
 *    vetter's ecc_targets list (e.g. vetter certified for "44" only, TN is "+1...").
 *
 *  FAIL-JURISDICTION     Vetter: Jurisdiction Violation
 *    VetterCert found, but the org's incorporation country / brand assertion country
 *    is NOT in the vetter's jurisdiction_targets list.
 *
 *  FAIL-ECC-JURISDICTION Vetter: ECC + Jurisdiction
 *    Both ECC and jurisdiction constraints are violated simultaneously.
 *
 *  INDETERMINATE         Vetter: Indeterminate
 *    VetterCertification credential NOT found via any "certification" edge on the
 *    TN/identity/brand credential. Common cause: TN allocation credentials issued
 *    with the basic TNAlloc schema (no "e" edges block) instead of the Extended
 *    TNAlloc schema (EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_).
 *    Fix: re-issue TNAlloc credentials with the extended schema so the issuer
 *    auto-injects the "certification" → VetterCert edge at issuance time.
 *    Non-blocking when ENFORCE_VETTER_CONSTRAINTS=false (default); overall_status
 *    is unaffected.
 *
 *  (absent)              Badge not shown
 *    No vetter constraint data in the verifier response. Happens when the dossier
 *    contains no TN/identity/brand credentials, or no orig.tn in PASSporT.
 */

const VVPDisplay = {

  placeholderLogo: 'img/vvp-logo-placeholder.svg',

  /**
   * Verification status configuration.
   * Maps X-VVP-Status header value → { label, icon, className }.
   */
  statusConfig: {
    VALID:         { label: 'Verified',      icon: '\u2713', className: 'valid' },
    INVALID:       { label: 'Not Verified',  icon: '\u2717', className: 'invalid' },
    INDETERMINATE: { label: 'Pending',       icon: '?',      className: 'indeterminate' },
    UNKNOWN:       { label: 'Unknown',       icon: '\u2014', className: 'unknown' },
  },

  /**
   * Vetter constraint status configuration.
   * Maps X-VVP-Vetter-Status header value → { label, className }.
   */
  vetterStatusConfig: {
    PASS:                    { label: 'Vetter: Authorized',              className: 'pass' },
    'FAIL-ECC':              { label: 'Vetter: ECC Violation',           className: 'fail' },
    'FAIL-JURISDICTION':     { label: 'Vetter: Jurisdiction Violation',  className: 'fail' },
    'FAIL-ECC-JURISDICTION': { label: 'Vetter: ECC + Jurisdiction',      className: 'fail' },
    INDETERMINATE:           { label: 'Vetter: Indeterminate',           className: 'vetter-indeterminate' },
  },

  /**
   * Extract VVP data from a SIP.js 0.15.x incoming session.
   * @param {Object} session - SIP.js InviteServerContext
   * @returns {Object} { brand_name, brand_logo, status, vetter_status, caller_number }
   */
  extractFromSIPSession(session) {
    const request = session.request;
    const headers = request?.headers || {};

    // SIP.js stores headers under unpredictable casing — iterate all
    // and match case-insensitively (proven pattern from existing phone)
    let brandName = null;
    let brandLogo = null;
    let status = null;
    let vetterStatus = null;

    for (const [name, values] of Object.entries(headers)) {
      const raw = Array.isArray(values) ? (values[0]?.raw || values[0]) : values;
      if (!raw) continue;

      let decoded;
      try {
        decoded = decodeURIComponent(String(raw).replace(/\+/g, ' '));
      } catch {
        decoded = String(raw);
      }

      const lower = name.toLowerCase();
      if (lower === 'x-vvp-brand-name')    brandName = decoded;
      else if (lower === 'x-vvp-brand-logo')  brandLogo = decoded;
      else if (lower === 'x-vvp-status')       status = decoded.toUpperCase();
      else if (lower === 'x-vvp-vetter-status') vetterStatus = decoded.toUpperCase();
    }

    // Fallback for brand name: From header display name, then URI user
    if (!brandName) {
      brandName = request?.from?.displayName
        || request?.from?.uri?.user
        || 'Unknown Caller';
    }

    if (!status) status = 'UNKNOWN';

    return {
      brand_name:    brandName,
      brand_logo:    brandLogo || this.placeholderLogo,
      status:        this.statusConfig[status] ? status : 'UNKNOWN',
      vetter_status: vetterStatus || null,
      caller_number: request?.from?.uri?.user || null,
    };
  },
};
