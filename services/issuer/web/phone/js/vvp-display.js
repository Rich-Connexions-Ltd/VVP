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

  placeholderLogo: '/static/phone/img/vvp-logo-placeholder.svg',

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
    const headers = session.request?.headers || {};

    const get = (name) => {
      // SIP.js stores headers keyed by their original casing
      const vals = headers[name] || headers[name.toLowerCase()];
      if (!vals) return null;
      const raw = Array.isArray(vals) ? (vals[0]?.raw || vals[0]) : vals;
      if (!raw) return null;
      try {
        return decodeURIComponent(String(raw).replace(/\+/g, ' '));
      } catch {
        return String(raw);
      }
    };

    const brandName = get('X-VVP-Brand-Name')
      || session.request?.from?.displayName
      || session.request?.from?.uri?.user
      || 'Unknown Caller';

    const rawStatus = (get('X-VVP-Status') || 'UNKNOWN').toUpperCase();

    return {
      brand_name:    brandName,
      brand_logo:    get('X-VVP-Brand-Logo') || this.placeholderLogo,
      status:        this.statusConfig[rawStatus] ? rawStatus : 'UNKNOWN',
      vetter_status: get('X-VVP-Vetter-Status')?.toUpperCase() || null,
      caller_number: session.request?.from?.uri?.user || null,
    };
  },
};
