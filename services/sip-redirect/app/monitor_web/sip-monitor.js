/**
 * VVP SIP Monitor Dashboard - Client JavaScript
 * Sprint 47: Core client logic for event display and polling
 * Sprint 48: WebSocket real-time updates, JWT parsing, PASSporT tab
 */

// =============================================================================
// STATE
// =============================================================================

const state = {
    events: [],
    lastEventId: 0,
    selectedEvent: null,
    pollingInterval: null,
    isPolling: false,
    ws: null,
    wsRetries: 0,
    wsRetryTimer: null,
    wsMode: 'disconnected',
};

// =============================================================================
// UTILITIES
// =============================================================================

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

/**
 * Format timestamp for display
 */
function formatTime(isoString) {
    try {
        const date = new Date(isoString);
        return date.toLocaleTimeString('en-GB', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    } catch (e) {
        return isoString;
    }
}

/**
 * Format timestamp with date for detail view
 */
function formatDateTime(isoString) {
    try {
        const date = new Date(isoString);
        return date.toLocaleString('en-GB', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    } catch (e) {
        return isoString;
    }
}

/**
 * API request helper with CSRF header
 */
async function apiRequest(url, options = {}) {
    const defaultHeaders = {
        'X-Requested-With': 'XMLHttpRequest',
    };

    if (options.body && typeof options.body === 'object') {
        defaultHeaders['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);
    }

    const response = await fetch(url, {
        ...options,
        headers: { ...defaultHeaders, ...options.headers },
    });

    if (response.status === 401) {
        // Session expired - redirect to login
        window.location.href = '/login';
        throw new Error('Session expired');
    }

    return response;
}

// =============================================================================
// EVENT RENDERING
// =============================================================================

/**
 * Render a single event row in the table
 */
function renderEventRow(event) {
    const row = document.createElement('tr');
    row.className = 'event-row';
    row.dataset.eventId = event.id;

    const serviceClass = event.service === 'SIGNING' ? 'service-signing' : 'service-verify';
    const statusClass = getVvpStatusClass(event.vvp_headers);

    row.innerHTML = `
        <td class="col-time">${escapeHtml(formatTime(event.timestamp))}</td>
        <td class="col-service"><span class="badge ${serviceClass}">${escapeHtml(event.service)}</span></td>
        <td class="col-from">${escapeHtml(event.from_tn || '-')}</td>
        <td class="col-to">${escapeHtml(event.to_tn || '-')}</td>
        <td class="col-status"><span class="badge ${statusClass}">${escapeHtml(event.response_code)}</span></td>
    `;

    row.addEventListener('click', () => showEventDetail(event));
    return row;
}

/**
 * Get CSS class for VVP status
 */
function getVvpStatusClass(vvpHeaders) {
    const status = vvpHeaders?.['X-VVP-Status'] || '';
    switch (status.toUpperCase()) {
        case 'VALID': return 'status-valid';
        case 'INVALID': return 'status-invalid';
        case 'INDETERMINATE': return 'status-indeterminate';
        default: return 'status-unknown';
    }
}

/**
 * Add new events to the table
 */
function addEventsToTable(newEvents) {
    const tbody = document.getElementById('event-tbody');
    const emptyRow = tbody.querySelector('.empty-row');

    if (emptyRow && newEvents.length > 0) {
        emptyRow.remove();
    }

    // Add new events at the top (newest first)
    newEvents.forEach(event => {
        state.events.unshift(event);
        const row = renderEventRow(event);
        tbody.insertBefore(row, tbody.firstChild);
    });

    // Update last event ID for polling
    if (newEvents.length > 0) {
        state.lastEventId = Math.max(state.lastEventId, ...newEvents.map(e => e.id));
    }

    updateCounts();
}

/**
 * Refresh all events from API
 */
async function refreshEvents() {
    try {
        const response = await apiRequest('/api/events');
        const data = await response.json();

        state.events = data.events || [];
        state.lastEventId = state.events.length > 0 ? state.events[0].id : 0;

        const tbody = document.getElementById('event-tbody');
        tbody.innerHTML = '';

        if (state.events.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="5">No events yet. Make a test call to see SIP traffic.</td>
                </tr>
            `;
        } else {
            state.events.forEach(event => {
                tbody.appendChild(renderEventRow(event));
            });
        }

        updateCounts(data.buffer_size, data.buffer_max);
        // Only update status if in polling mode (don't overwrite WebSocket status)
        if (state.wsMode === 'polling') {
            updateConnectionStatus('polling');
        }

    } catch (error) {
        console.error('Failed to refresh events:', error);
        if (state.wsMode !== 'websocket') {
            updateConnectionStatus('error');
        }
    }
}

/**
 * Poll for new events since last ID
 */
async function pollEvents() {
    if (state.isPolling) return;

    state.isPolling = true;

    try {
        const response = await apiRequest(`/api/events/since/${state.lastEventId}`);
        const data = await response.json();

        if (data.events && data.events.length > 0) {
            // Reverse to get oldest first for correct insertion order
            addEventsToTable(data.events.reverse());
        }

        // Maintain polling status (don't overwrite WebSocket status)
        if (state.wsMode === 'polling') {
            updateConnectionStatus('polling');
        }

    } catch (error) {
        console.error('Polling error:', error);
        if (state.wsMode === 'polling') {
            updateConnectionStatus('error');
        }
    } finally {
        state.isPolling = false;
    }
}

// =============================================================================
// WEBSOCKET (Sprint 48)
// =============================================================================

/**
 * Connect to WebSocket for real-time event streaming
 */
function connectWebSocket() {
    if (state.ws && state.ws.readyState <= WebSocket.OPEN) {
        return; // Already connected or connecting
    }

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${location.host}/ws`;

    updateConnectionStatus('connecting');
    state.ws = new WebSocket(url);

    state.ws.onopen = () => {
        state.wsRetries = 0;
        state.wsMode = 'websocket';
        updateConnectionStatus('connected');

        // Stop polling if running
        if (state.pollingInterval) {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
        }

        console.log('WebSocket connected');
    };

    state.ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            onWsMessage(msg);
        } catch (e) {
            console.error('WebSocket message parse error:', e);
        }
    };

    state.ws.onclose = (event) => {
        state.ws = null;
        onWsClose(event);
    };

    state.ws.onerror = () => {
        // onclose will fire after onerror, handling is done there
        console.error('WebSocket error');
    };
}

/**
 * Handle incoming WebSocket message by type
 */
function onWsMessage(msg) {
    switch (msg.type) {
        case 'event':
            addEventsToTable([msg.data]);
            break;
        case 'heartbeat':
            // Connection alive, nothing to do
            break;
        case 'error':
            if (msg.message === 'session_expired') {
                updateConnectionStatus('error');
                // Terminal - redirect to login
                setTimeout(() => { window.location.href = '/login'; }, 2000);
            }
            break;
    }
}

/**
 * Handle WebSocket close - route by close code
 */
function onWsClose(event) {
    if (event.code === 4001) {
        // Session expired - terminal, do NOT reconnect
        updateConnectionStatus('error');
        setTimeout(() => { window.location.href = '/login'; }, 2000);
        return;
    }

    if (event.code === 1000) {
        // Normal close
        state.wsMode = 'disconnected';
        updateConnectionStatus('disconnected');
        return;
    }

    // Unexpected close - schedule reconnect
    scheduleReconnect();
}

/**
 * Schedule WebSocket reconnect with exponential backoff
 */
function scheduleReconnect() {
    state.wsRetries++;

    if (state.wsRetries > 5) {
        // Fall back to polling
        fallbackToPolling();
        return;
    }

    const delay = Math.min(1000 * Math.pow(2, state.wsRetries - 1), 30000);
    console.log(`WebSocket reconnect in ${delay}ms (attempt ${state.wsRetries}/5)`);
    updateConnectionStatus('connecting');

    state.wsRetryTimer = setTimeout(() => {
        state.wsRetryTimer = null;
        connectWebSocket();
    }, delay);
}

/**
 * Fall back to polling when WebSocket is unavailable
 */
function fallbackToPolling() {
    console.log('WebSocket unavailable, falling back to polling');
    state.wsMode = 'polling';
    updateConnectionStatus('polling');

    if (!state.pollingInterval) {
        state.pollingInterval = setInterval(pollEvents, 2000);
    }
}

// =============================================================================
// JWT PARSING (Sprint 48)
// =============================================================================

/**
 * Decode base64url string (RFC 4648 Section 5)
 */
function base64urlDecode(str) {
    try {
        let padded = str.replace(/-/g, '+').replace(/_/g, '/');
        while (padded.length % 4) padded += '=';
        return atob(padded);
    } catch (e) {
        return null;
    }
}

/**
 * Parse a JWT string into header, payload, signature
 * Returns null if invalid format
 */
function parseJWT(jwt) {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    try {
        const headerStr = base64urlDecode(parts[0]);
        const payloadStr = base64urlDecode(parts[1]);
        if (!headerStr || !payloadStr) return null;
        const header = JSON.parse(headerStr);
        const payload = JSON.parse(payloadStr);
        return {
            header,
            payload,
            signature: parts[2],
            isVVP: header.ppt === 'vvp',
        };
    } catch (e) {
        return null;
    }
}

/**
 * Extract Identity header JWT and parameters (RFC 8224)
 * Format: Identity: <jwt>;info=<url>;alg=ES256
 */
function extractIdentityJWT(headers) {
    const identityValue = headers['Identity'] || headers['identity'];
    if (!identityValue) return null;

    const parts = identityValue.split(';');
    const jwt = parts[0].trim();
    const params = {};
    for (let i = 1; i < parts.length; i++) {
        const [key, ...valueParts] = parts[i].split('=');
        if (key && valueParts.length) {
            params[key.trim()] = valueParts.join('=').trim();
        }
    }
    return { jwt, info: params.info || null, alg: params.alg || null, params };
}

/**
 * Parse P-VVP-Identity header (base64url-encoded JSON)
 * Expected fields: kid, ppt, evd, iat
 */
function parsePVVPIdentity(value) {
    try {
        const jsonStr = base64urlDecode(value);
        if (!jsonStr) return null;
        const decoded = JSON.parse(jsonStr);
        return {
            decoded,
            isValid: decoded.ppt === 'vvp',
        };
    } catch (e) {
        return null;
    }
}

// =============================================================================
// EVENT DETAIL VIEW
// =============================================================================

/**
 * Show event detail panel
 */
function showEventDetail(event) {
    state.selectedEvent = event;

    const panel = document.getElementById('detail-panel');
    panel.style.display = 'block';

    // Highlight selected row
    document.querySelectorAll('.event-row').forEach(row => {
        row.classList.remove('selected');
        if (row.dataset.eventId == event.id) {
            row.classList.add('selected');
        }
    });

    // Show summary tab by default
    showTab('summary');
}

/**
 * Show specific tab content
 */
function showTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.detail-tabs .tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    // Render content
    const content = document.getElementById('detail-content');
    const event = state.selectedEvent;

    if (!event) {
        content.innerHTML = '<p>No event selected</p>';
        return;
    }

    switch (tabName) {
        case 'summary':
            content.innerHTML = renderSummaryTab(event);
            break;
        case 'headers':
            content.innerHTML = renderHeadersTab(event);
            break;
        case 'vvp':
            content.innerHTML = renderVvpTab(event);
            break;
        case 'passport':
            content.innerHTML = renderPassportTab(event);
            break;
        case 'raw':
            content.innerHTML = renderRawTab(event);
            break;
        default:
            content.innerHTML = '<p>Unknown tab</p>';
    }
}

/**
 * Render summary tab
 */
function renderSummaryTab(event) {
    return `
        <div class="summary-grid">
            <div class="summary-item">
                <label>Event ID</label>
                <value>${escapeHtml(event.id)}</value>
            </div>
            <div class="summary-item">
                <label>Timestamp</label>
                <value>${escapeHtml(formatDateTime(event.timestamp))}</value>
            </div>
            <div class="summary-item">
                <label>Service</label>
                <value><span class="badge ${event.service === 'SIGNING' ? 'service-signing' : 'service-verify'}">${escapeHtml(event.service)}</span></value>
            </div>
            <div class="summary-item">
                <label>Source</label>
                <value>${escapeHtml(event.source_addr)}</value>
            </div>
            <div class="summary-item">
                <label>Method</label>
                <value>${escapeHtml(event.method)}</value>
            </div>
            <div class="summary-item">
                <label>Request URI</label>
                <value>${escapeHtml(event.request_uri)}</value>
            </div>
            <div class="summary-item">
                <label>From TN</label>
                <value>${escapeHtml(event.from_tn || '-')}</value>
            </div>
            <div class="summary-item">
                <label>To TN</label>
                <value>${escapeHtml(event.to_tn || '-')}</value>
            </div>
            <div class="summary-item">
                <label>Call-ID</label>
                <value class="monospace">${escapeHtml(event.call_id)}</value>
            </div>
            <div class="summary-item">
                <label>Response</label>
                <value>${escapeHtml(event.response_code)}</value>
            </div>
            <div class="summary-item full-width">
                <label>Redirect URI</label>
                <value>${escapeHtml(event.redirect_uri || '-')}</value>
            </div>
        </div>
    `;
}

/**
 * Render all headers tab
 */
function renderHeadersTab(event) {
    const headers = event.headers || {};
    const rows = Object.entries(headers)
        .map(([name, value]) => `
            <tr>
                <td class="header-name">${escapeHtml(name)}</td>
                <td class="header-value">${escapeHtml(value)}</td>
            </tr>
        `)
        .join('');

    if (!rows) {
        return '<p class="empty-message">No headers found</p>';
    }

    return `
        <table class="headers-table">
            <thead>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
    `;
}

/**
 * Render VVP headers tab
 */
function renderVvpTab(event) {
    const vvpHeaders = event.vvp_headers || {};
    const entries = Object.entries(vvpHeaders);

    if (entries.length === 0) {
        return '<p class="empty-message">No VVP headers found in this request</p>';
    }

    const rows = entries
        .map(([name, value]) => `
            <tr>
                <td class="header-name">${escapeHtml(name)}</td>
                <td class="header-value">${escapeHtml(value)}</td>
            </tr>
        `)
        .join('');

    // Check for VVP status
    const status = vvpHeaders['X-VVP-Status'] || '';
    const statusClass = getVvpStatusClass(vvpHeaders);

    let statusBanner = '';
    if (status) {
        statusBanner = `
            <div class="vvp-status-banner ${statusClass}">
                VVP Status: <strong>${escapeHtml(status)}</strong>
            </div>
        `;
    }

    return `
        ${statusBanner}
        <table class="headers-table vvp-headers">
            <thead>
                <tr>
                    <th>VVP Header</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
    `;
}

/**
 * Render raw SIP tab
 */
function renderRawTab(event) {
    return `
        <pre class="raw-sip">${escapeHtml(event.raw_request || 'No raw data available')}</pre>
    `;
}

/**
 * Render PASSporT tab - decoded JWT and P-VVP-Identity
 */
function renderPassportTab(event) {
    let html = '';
    const headers = event.headers || {};
    const vvpHeaders = event.vvp_headers || {};

    // 1. Identity header JWT (RFC 8224 PASSporT)
    const identity = extractIdentityJWT(headers);
    if (identity) {
        const parsed = parseJWT(identity.jwt);
        if (parsed) {
            html += renderJWTSection('Identity PASSporT', parsed, identity.params);
        } else {
            html += '<div class="passport-error">Identity header present but JWT is malformed</div>';
        }
    }

    // 2. P-VVP-Identity header (base64url JSON)
    const pvvpValue = vvpHeaders['P-VVP-Identity'] || headers['P-VVP-Identity'];
    if (pvvpValue) {
        const pvvp = parsePVVPIdentity(pvvpValue);
        if (pvvp) {
            html += renderPVVPSection('P-VVP-Identity', pvvp);
        } else {
            html += '<div class="passport-error">P-VVP-Identity present but failed to decode</div>';
        }
    }

    // 3. No PASSporT data
    if (!html) {
        html = '<p class="empty-message">No PASSporT or VVP identity headers found in this request</p>';
    }

    return html;
}

/**
 * Render decoded JWT section with VVP field highlighting
 */
function renderJWTSection(title, parsed, params) {
    const vvpBadge = parsed.isVVP
        ? '<span class="badge status-valid">VVP</span>'
        : '<span class="badge status-invalid">NOT VVP</span>';

    const vvpHeaderFields = ['ppt', 'kid', 'evd'];
    const vvpPayloadFields = ['orig', 'dest', 'iat'];

    let html = `<div class="passport-section">`;
    html += `<h3>${escapeHtml(title)} ${vvpBadge}</h3>`;

    // Identity header parameters (info, alg)
    if (params && Object.keys(params).length > 0) {
        html += `<div class="passport-params">`;
        for (const [key, value] of Object.entries(params)) {
            html += `<span class="passport-param"><strong>${escapeHtml(key)}:</strong> ${escapeHtml(value)}</span>`;
        }
        html += `</div>`;
    }

    // JWT Header
    html += `<h4>Header</h4>`;
    html += `<div class="passport-json">`;
    html += renderJsonWithHighlight(parsed.header, vvpHeaderFields);
    html += `</div>`;

    // JWT Payload
    html += `<h4>Payload</h4>`;
    html += `<div class="passport-json">`;
    html += renderJsonWithHighlight(parsed.payload, vvpPayloadFields);
    html += `</div>`;

    // Signature (truncated)
    const sig = parsed.signature || '';
    const sigDisplay = sig.length > 40 ? sig.substring(0, 40) + '...' : sig;
    html += `<h4>Signature</h4>`;
    html += `<div class="passport-signature">`;
    html += `<code>${escapeHtml(sigDisplay)}</code>`;
    html += `</div>`;

    html += `</div>`;
    return html;
}

/**
 * Render P-VVP-Identity section with VVP field highlighting
 */
function renderPVVPSection(title, pvvp) {
    const validBadge = pvvp.isValid
        ? '<span class="badge status-valid">Valid ppt</span>'
        : '<span class="badge status-invalid">Invalid ppt</span>';

    const vvpFields = ['ppt', 'kid', 'evd', 'iat'];

    let html = `<div class="passport-section">`;
    html += `<h3>${escapeHtml(title)} ${validBadge}</h3>`;
    html += `<div class="passport-json">`;
    html += renderJsonWithHighlight(pvvp.decoded, vvpFields);
    html += `</div>`;
    html += `</div>`;
    return html;
}

/**
 * Render JSON object with VVP field highlighting
 */
function renderJsonWithHighlight(obj, highlightFields) {
    let html = '<table class="passport-fields">';
    for (const [key, value] of Object.entries(obj)) {
        const isHighlighted = highlightFields.includes(key);
        const cls = isHighlighted ? ' class="passport-field"' : '';
        let displayValue = value;
        if (typeof value === 'object' && value !== null) {
            displayValue = JSON.stringify(value, null, 2);
        } else if (key === 'iat' && typeof value === 'number') {
            // Format iat as human-readable date alongside epoch
            const date = new Date(value * 1000);
            displayValue = `${value} (${date.toISOString()})`;
        }
        html += `<tr${cls}>`;
        html += `<td class="passport-key">${escapeHtml(key)}</td>`;
        html += `<td class="passport-value">${escapeHtml(String(displayValue))}</td>`;
        html += `</tr>`;
    }
    html += '</table>';
    return html;
}

// =============================================================================
// UI UPDATES
// =============================================================================

/**
 * Update buffer and event counts
 */
function updateCounts(bufferCount, bufferMax) {
    const countEl = document.getElementById('buffer-count');
    const maxEl = document.getElementById('buffer-max');
    const eventCountEl = document.getElementById('event-count');

    if (bufferCount !== undefined) {
        countEl.textContent = bufferCount;
    }
    if (bufferMax !== undefined) {
        maxEl.textContent = bufferMax;
    }

    eventCountEl.textContent = state.events.length;
}

/**
 * Update connection status indicator
 */
function updateConnectionStatus(status) {
    const el = document.getElementById('connection-status');

    el.classList.remove(
        'status-connected', 'status-disconnected', 'status-error',
        'status-connecting', 'status-polling'
    );

    switch (status) {
        case 'connected':
            el.classList.add('status-connected');
            el.textContent = 'Connected (WebSocket)';
            break;
        case 'connecting':
            el.classList.add('status-connecting');
            el.textContent = 'Connecting...';
            break;
        case 'polling':
            el.classList.add('status-polling');
            el.textContent = 'Connected (Polling)';
            break;
        case 'error':
            el.classList.add('status-error');
            el.textContent = 'Error';
            break;
        default:
            el.classList.add('status-disconnected');
            el.textContent = 'Disconnected';
    }
}

// =============================================================================
// ACTIONS
// =============================================================================

/**
 * Clear event buffer
 */
async function clearBuffer() {
    if (!confirm('Clear all events from the buffer?')) return;

    try {
        const response = await apiRequest('/api/clear', { method: 'POST' });
        const data = await response.json();

        if (data.success) {
            state.events = [];
            state.lastEventId = 0;
            state.selectedEvent = null;

            const tbody = document.getElementById('event-tbody');
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="5">No events yet. Make a test call to see SIP traffic.</td>
                </tr>
            `;

            document.getElementById('detail-panel').style.display = 'none';
            updateCounts(0);
        }
    } catch (error) {
        console.error('Failed to clear buffer:', error);
        alert('Failed to clear buffer');
    }
}

/**
 * Logout
 */
async function logout() {
    try {
        await apiRequest('/api/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout error:', error);
    }
    window.location.href = '/login';
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the dashboard
 */
function init() {
    // Tab switching
    document.querySelectorAll('.detail-tabs .tab').forEach(btn => {
        btn.addEventListener('click', () => showTab(btn.dataset.tab));
    });

    // Close detail panel
    document.getElementById('close-detail')?.addEventListener('click', () => {
        document.getElementById('detail-panel').style.display = 'none';
        state.selectedEvent = null;
        document.querySelectorAll('.event-row.selected').forEach(r => r.classList.remove('selected'));
    });

    // Clear button
    document.getElementById('clear-btn')?.addEventListener('click', clearBuffer);

    // Logout button
    document.getElementById('logout-btn')?.addEventListener('click', logout);

    // Initial load
    refreshEvents();

    // Try WebSocket first (falls back to polling on failure)
    connectWebSocket();

    console.log('VVP SIP Monitor initialized');
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
