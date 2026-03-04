/**
 * VVP Display Module for PWA SIP Client
 *
 * Extracts VVP verification data from SIP.js 0.15.x session headers
 * and provides status/badge configuration for the call overlay UI.
 *
 * SIP Headers (set by FreeSWITCH dialplan after verification):
 *   X-VVP-Brand-Name    - Verified caller brand name
 *   X-VVP-Brand-Logo    - URL to brand logo
 *   X-VVP-Status        - VALID | INVALID | INDETERMINATE | UNKNOWN
 *   X-VVP-Vetter-Status - PASS | FAIL-ECC | FAIL-JURISDICTION | FAIL-ECC-JURISDICTION | INDETERMINATE
 */

const VVPDisplay = {

  placeholderLogo: 'img/vvp-logo-placeholder.svg',

  /** Verification status configuration */
  statusConfig: {
    VALID:         { label: 'Verified',      icon: '\u2713', className: 'valid' },
    INVALID:       { label: 'Not Verified',  icon: '\u2717', className: 'invalid' },
    INDETERMINATE: { label: 'Pending',       icon: '?',      className: 'indeterminate' },
    UNKNOWN:       { label: 'Unknown',       icon: '\u2014', className: 'unknown' },
  },

  /** Vetter constraint status configuration */
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
