/**
 * VVP Display Module
 *
 * Extracts VVP (Verified Voice Protocol) data from Verto call parameters
 * and displays brand name, logo, and verification status.
 *
 * Channel variables from FreeSWITCH:
 * - vvp_brand_name: Verified caller brand name
 * - vvp_brand_logo: URL to brand logo
 * - vvp_status: VALID | INVALID | INDETERMINATE | UNKNOWN
 * - vvp_vetter_status: PASS | FAIL-ECC | FAIL-JURISDICTION | FAIL-ECC-JURISDICTION (Sprint 62)
 */

const VVPDisplay = {
    // Status badge configuration
    statusConfig: {
        'VALID': {
            label: 'Verified',
            className: 'vvp-status-valid',
            icon: '✓'
        },
        'INVALID': {
            label: 'Not Verified',
            className: 'vvp-status-invalid',
            icon: '✗'
        },
        'INDETERMINATE': {
            label: 'Pending',
            className: 'vvp-status-indeterminate',
            icon: '?'
        },
        'UNKNOWN': {
            label: 'Unknown',
            className: 'vvp-status-unknown',
            icon: '—'
        }
    },

    // Sprint 62: Vetter constraint status badge configuration
    vetterStatusConfig: {
        'PASS': {
            label: 'Vetter: Authorized',
            className: 'vvp-vetter-pass',
            icon: '✓'
        },
        'FAIL-ECC': {
            label: 'Vetter: ECC Violation',
            className: 'vvp-vetter-fail',
            icon: '!'
        },
        'FAIL-JURISDICTION': {
            label: 'Vetter: Jurisdiction Violation',
            className: 'vvp-vetter-fail',
            icon: '!'
        },
        'FAIL-ECC-JURISDICTION': {
            label: 'Vetter: ECC + Jurisdiction Violation',
            className: 'vvp-vetter-fail',
            icon: '!'
        }
    },

    // Default placeholder logo
    placeholderLogo: 'img/vvp-logo-placeholder.svg',

    /**
     * Extract VVP data from Verto call parameters
     * @param {Object} call - Verto call object
     * @returns {Object} VVP data with brand_name, brand_logo, status
     */
    extractVVPData(call) {
        const params = call?.params || {};

        // Try different variable naming conventions
        const brandName = this.decodeValue(
            params.vvp_brand_name ||
            params['vvp_brand_name'] ||
            params.caller_id_name ||
            'Unknown Caller'
        );

        const brandLogo = this.decodeValue(
            params.vvp_brand_logo ||
            params['vvp_brand_logo'] ||
            ''
        );

        const status = (
            params.vvp_status ||
            params['vvp_status'] ||
            'UNKNOWN'
        ).toUpperCase();

        // Sprint 62: Vetter constraint status
        const vetterStatus = (
            params.vvp_vetter_status ||
            params['vvp_vetter_status'] ||
            ''
        ).toUpperCase() || null;

        return {
            brand_name: brandName,
            brand_logo: brandLogo || this.placeholderLogo,
            status: this.statusConfig[status] ? status : 'UNKNOWN',
            vetter_status: vetterStatus,
            raw_params: params
        };
    },

    /**
     * Decode URL-encoded value
     * @param {string} value - Potentially URL-encoded string
     * @returns {string} Decoded string
     */
    decodeValue(value) {
        if (!value) return '';
        try {
            return decodeURIComponent(value.replace(/\+/g, ' '));
        } catch (e) {
            return value;
        }
    },

    /**
     * Create status badge element
     * @param {string} status - VVP status
     * @returns {HTMLElement} Badge element
     */
    createStatusBadge(status) {
        const config = this.statusConfig[status] || this.statusConfig['UNKNOWN'];
        const badge = document.createElement('span');
        badge.className = `vvp-status-badge ${config.className}`;
        badge.innerHTML = `<span class="vvp-status-icon">${config.icon}</span> ${config.label}`;
        return badge;
    },

    /**
     * Create vetter status badge element (Sprint 62)
     * @param {string|null} vetterStatus - Vetter constraint status
     * @returns {HTMLElement|null} Badge element or null if no status
     */
    createVetterBadge(vetterStatus) {
        if (!vetterStatus) return null;
        const config = this.vetterStatusConfig[vetterStatus];
        if (!config) return null;
        const badge = document.createElement('span');
        badge.className = `vvp-vetter-badge ${config.className}`;
        badge.innerHTML = `<span class="vvp-status-icon">${config.icon}</span> ${config.label}`;
        return badge;
    },

    /**
     * Create brand logo element with fallback
     * @param {string} logoUrl - URL to brand logo
     * @param {string} brandName - Brand name for alt text
     * @returns {HTMLElement} Logo container element
     */
    createLogoElement(logoUrl, brandName) {
        const container = document.createElement('div');
        container.className = 'vvp-logo-container';

        const img = document.createElement('img');
        img.className = 'vvp-brand-logo';
        img.alt = brandName;
        img.src = logoUrl;

        // Fallback to placeholder on error
        img.onerror = () => {
            img.src = this.placeholderLogo;
        };

        container.appendChild(img);
        return container;
    },

    /**
     * Create full VVP display panel
     * @param {Object} vvpData - Extracted VVP data
     * @returns {HTMLElement} VVP panel element
     */
    createDisplayPanel(vvpData) {
        const panel = document.createElement('div');
        panel.className = 'vvp-display-panel';
        panel.id = 'vvp-caller-info';

        // Logo
        const logo = this.createLogoElement(vvpData.brand_logo, vvpData.brand_name);
        panel.appendChild(logo);

        // Brand name
        const nameEl = document.createElement('div');
        nameEl.className = 'vvp-brand-name';
        nameEl.textContent = vvpData.brand_name;
        panel.appendChild(nameEl);

        // Status badge
        const badge = this.createStatusBadge(vvpData.status);
        panel.appendChild(badge);

        // Sprint 62: Vetter constraint badge (shown below main status)
        const vetterBadge = this.createVetterBadge(vvpData.vetter_status);
        if (vetterBadge) {
            panel.appendChild(vetterBadge);
        }

        return panel;
    },

    /**
     * Update or create VVP display in target container
     * @param {Object} vvpData - Extracted VVP data
     * @param {string|HTMLElement} targetId - Target container ID or element
     */
    updateDisplay(vvpData, targetId = 'vvp-display-container') {
        const target = typeof targetId === 'string'
            ? document.getElementById(targetId)
            : targetId;

        if (!target) {
            console.warn('[VVP] Display container not found:', targetId);
            return;
        }

        // Remove existing panel
        const existing = document.getElementById('vvp-caller-info');
        if (existing) {
            existing.remove();
        }

        // Create and insert new panel
        const panel = this.createDisplayPanel(vvpData);
        target.appendChild(panel);

        console.log('[VVP] Display updated:', vvpData);
    },

    /**
     * Hide VVP display
     */
    hideDisplay() {
        const panel = document.getElementById('vvp-caller-info');
        if (panel) {
            panel.classList.add('vvp-hidden');
        }
    },

    /**
     * Show VVP display
     */
    showDisplay() {
        const panel = document.getElementById('vvp-caller-info');
        if (panel) {
            panel.classList.remove('vvp-hidden');
        }
    },

    /**
     * Initialize VVP display with Verto session
     * @param {Object} vertoSession - Verto session object
     * @param {string} containerId - Container element ID
     */
    init(vertoSession, containerId = 'vvp-display-container') {
        console.log('[VVP] Initializing VVP Display module');

        // Store reference
        this.session = vertoSession;
        this.containerId = containerId;

        // Hook into call events if verto.js provides hooks
        if (vertoSession && typeof vertoSession.subscribe === 'function') {
            vertoSession.subscribe('verto.display', (data) => {
                console.log('[VVP] Received verto.display event:', data);
            });
        }
    },

    /**
     * Handle incoming call - extract and display VVP data
     * @param {Object} call - Verto call object
     */
    handleIncomingCall(call) {
        console.log('[VVP] Handling incoming call');
        const vvpData = this.extractVVPData(call);
        this.updateDisplay(vvpData, this.containerId);
        this.showDisplay();
    },

    /**
     * Handle call ended - hide display
     */
    handleCallEnded() {
        console.log('[VVP] Call ended, hiding display');
        this.hideDisplay();
    }
};

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VVPDisplay;
}
