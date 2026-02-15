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
        window.location.href = 'login';
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
    const statusClass = getVvpStatusClass(event.vvp_headers, event.response_vvp_headers);

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
function getVvpStatusClass(vvpHeaders, responseVvpHeaders) {
    const status = responseVvpHeaders?.['X-VVP-Status']
        || vvpHeaders?.['X-VVP-Status']
        || '';
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
        const response = await apiRequest('api/events');
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
        const response = await apiRequest(`api/events/since/${state.lastEventId}`);
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
    const basePath = location.pathname.replace(/[^/]*$/, '');
    const url = `${protocol}//${location.host}${basePath}ws`;

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

        // Send keepalive every 20s to reset server idle timer
        if (state.wsKeepalive) clearInterval(state.wsKeepalive);
        state.wsKeepalive = setInterval(() => {
            if (state.ws && state.ws.readyState === WebSocket.OPEN) {
                state.ws.send(JSON.stringify({type: 'ping'}));
            }
        }, 20000);

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
        if (state.wsKeepalive) {
            clearInterval(state.wsKeepalive);
            state.wsKeepalive = null;
        }
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
                setTimeout(() => { window.location.href = 'login'; }, 2000);
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
        setTimeout(() => { window.location.href = 'login'; }, 2000);
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
        case 'request':
            content.innerHTML = renderRequestTab(event);
            break;
        case 'response':
            content.innerHTML = renderResponseTab(event);
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
 * Check if a header name is a VVP-specific header
 */
function isVvpHeader(name) {
    const lower = name.toLowerCase();
    return lower.startsWith('x-vvp-') || lower.startsWith('p-vvp-') || lower === 'identity';
}

/**
 * Get SIP reason phrase for a response code
 */
function getReasonPhrase(code) {
    const reasons = {
        200: 'OK',
        302: 'Moved Temporarily',
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        500: 'Server Internal Error',
    };
    return reasons[code] || '';
}

/**
 * Render "Open in VVP Explorer" button for a PASSporT JWT
 */
function renderExplorerButton(jwt) {
    const url = `https://vvp.rcnx.io/verify/explore?jwt=${encodeURIComponent(jwt)}`;
    return `
        <div class="explorer-link">
            <a href="${escapeHtml(url)}" target="_blank" rel="noopener" class="btn btn-primary explorer-btn">
                Open in VVP Explorer &#x2197;
            </a>
        </div>
    `;
}

/**
 * Render request tab — shows service context, VVP headers, and all SIP headers
 */
function renderRequestTab(event) {
    const service = event.service || 'SIGNING';
    const serviceClass = service === 'SIGNING' ? 'service-signing' : 'service-verify';
    const serviceLabel = service === 'SIGNING' ? 'Signing Request' : 'Verification Request';
    const headers = event.headers || {};
    const vvpHeaders = event.vvp_headers || {};

    let html = '';

    // Service context banner
    html += `
        <div class="request-context">
            <span class="badge ${serviceClass}">${escapeHtml(service)}</span>
            <span class="context-label">${escapeHtml(serviceLabel)}</span>
        </div>
    `;

    // VVP headers section (highlighted)
    const vvpEntries = Object.entries(vvpHeaders);
    if (vvpEntries.length > 0) {
        html += '<h3 class="section-heading">VVP Headers</h3>';
        html += '<table class="headers-table vvp-headers"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
        for (const [name, value] of vvpEntries) {
            html += `
                <tr class="vvp-highlight">
                    <td class="header-name">${escapeHtml(name)}</td>
                    <td class="header-value">${escapeHtml(value)}</td>
                </tr>
            `;
        }
        html += '</tbody></table>';
    }

    // All SIP headers
    const headerEntries = Object.entries(headers);
    if (headerEntries.length > 0) {
        html += '<h3 class="section-heading">All SIP Headers</h3>';
        html += '<table class="headers-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
        for (const [name, value] of headerEntries) {
            const cls = isVvpHeader(name) ? ' class="vvp-highlight"' : '';
            html += `
                <tr${cls}>
                    <td class="header-name">${escapeHtml(name)}</td>
                    <td class="header-value">${escapeHtml(value)}</td>
                </tr>
            `;
        }
        html += '</tbody></table>';
    }

    if (vvpEntries.length === 0 && headerEntries.length === 0) {
        html = '<p class="empty-message">No request headers found</p>';
    }

    return html;
}

/**
 * Render response tab — shows response code, redirect URI, VVP status, response headers, Explorer link
 */
function renderResponseTab(event) {
    const responseVvpHeaders = event.response_vvp_headers || {};
    const responseCode = event.response_code;
    const redirectUri = event.redirect_uri;

    let html = '';

    // Response summary
    const reason = getReasonPhrase(responseCode);
    const codeClass = responseCode >= 200 && responseCode < 400 ? 'status-valid'
                    : responseCode >= 400 ? 'status-invalid'
                    : 'status-unknown';

    html += '<div class="response-summary">';
    html += `
        <div class="response-field">
            <label>Response Code</label>
            <value><span class="badge ${codeClass}">${escapeHtml(String(responseCode))} ${escapeHtml(reason)}</span></value>
        </div>
    `;
    if (redirectUri) {
        html += `
            <div class="response-field">
                <label>Redirect URI</label>
                <value class="monospace" style="word-break: break-all; font-size: 0.8125rem;">${escapeHtml(redirectUri)}</value>
            </div>
        `;
    }
    html += '</div>';

    // VVP Status banner
    const status = responseVvpHeaders['X-VVP-Status'] || '';
    if (status) {
        const statusClass = getVvpStatusClass({}, responseVvpHeaders);
        html += `
            <div class="vvp-status-banner ${statusClass}">
                VVP Status: <strong>${escapeHtml(status)}</strong>
            </div>
        `;
    }

    // Sprint 62: Vetter constraint status sub-banner
    const vetterStatus = responseVvpHeaders['X-VVP-Vetter-Status'] || '';
    if (vetterStatus) {
        const vetterClass = vetterStatus === 'PASS' ? 'status-valid'
            : vetterStatus === 'INDETERMINATE' ? 'status-indeterminate'
            : 'status-invalid';
        html += `
            <div class="vvp-status-banner ${vetterClass}" style="font-size: 0.85em; margin-top: 0.25rem;">
                Vetter: <strong>${escapeHtml(vetterStatus)}</strong>
            </div>
        `;
    }

    // Response VVP headers table
    const entries = Object.entries(responseVvpHeaders);
    if (entries.length > 0) {
        html += '<table class="headers-table vvp-headers"><thead><tr><th>Response Header</th><th>Value</th></tr></thead><tbody>';
        for (const [name, value] of entries) {
            html += `
                <tr>
                    <td class="header-name">${escapeHtml(name)}</td>
                    <td class="header-value">${escapeHtml(value)}</td>
                </tr>
            `;
        }
        html += '</tbody></table>';
    } else {
        html += '<p class="empty-message">No VVP headers in response</p>';
    }

    // VVP Explorer button if PASSporT JWT available
    const passportJwt = responseVvpHeaders['P-VVP-Passport'];
    if (passportJwt) {
        html += renderExplorerButton(passportJwt);
    }

    return html;
}

/**
 * Render raw SIP tab
 * Sprint 48: Shows raw request/response if captured, otherwise reconstructs from headers
 */
function renderRawTab(event) {
    let html = '';

    if (event.raw_request) {
        html += '<h3>Request</h3>';
        html += `<pre class="raw-sip">${escapeHtml(event.raw_request)}</pre>`;
    }

    if (event.raw_response) {
        html += '<h3>Response</h3>';
        html += `<pre class="raw-sip">${escapeHtml(event.raw_response)}</pre>`;
    }

    // Fallback: reconstruct from event data
    if (!html) {
        html = reconstructRawSip(event);
    }

    return html;
}

/**
 * Reconstruct a raw SIP view from event headers and metadata
 */
function reconstructRawSip(event) {
    let html = '';

    // Reconstruct request
    const headers = event.headers || {};
    const headerEntries = Object.entries(headers);
    if (headerEntries.length > 0) {
        let raw = `${event.method || 'INVITE'} ${event.request_uri || '?'} SIP/2.0\r\n`;
        for (const [name, value] of headerEntries) {
            raw += `${name}: ${value}\r\n`;
        }
        raw += '\r\n';
        html += '<h3>Request (reconstructed)</h3>';
        html += `<pre class="raw-sip">${escapeHtml(raw)}</pre>`;
    }

    // Reconstruct response from response_vvp_headers
    const responseVvp = event.response_vvp_headers || {};
    const responseEntries = Object.entries(responseVvp);
    if (event.response_code && responseEntries.length > 0) {
        const reason = getReasonPhrase(event.response_code) || 'OK';
        let raw = `SIP/2.0 ${event.response_code} ${reason}\r\n`;
        for (const [name, value] of responseEntries) {
            raw += `${name}: ${value}\r\n`;
        }
        if (event.redirect_uri) {
            raw += `Contact: <${event.redirect_uri}>\r\n`;
        }
        raw += 'Content-Length: 0\r\n\r\n';
        html += '<h3>Response (reconstructed)</h3>';
        html += `<pre class="raw-sip">${escapeHtml(raw)}</pre>`;
    }

    if (!html) {
        html = '<p class="empty-message">No raw SIP data available</p>';
    }

    return html;
}

/**
 * Render PASSporT tab - decoded JWT and P-VVP-Identity
 * Sprint 48: Also checks response_vvp_headers for signing events
 */
function renderPassportTab(event) {
    let html = '';
    const headers = event.headers || {};
    const vvpHeaders = event.vvp_headers || {};
    const responseVvpHeaders = event.response_vvp_headers || {};

    // 1. Identity header JWT from request (RFC 8224 PASSporT)
    const identity = extractIdentityJWT(headers);
    if (identity) {
        const parsed = parseJWT(identity.jwt);
        if (parsed) {
            html += renderJWTSection('Identity PASSporT (Request)', parsed, identity.params, identity.jwt);
        } else {
            html += '<div class="passport-error">Identity header present but JWT is malformed</div>';
        }
    }

    // 2. P-VVP-Passport from response (signed PASSporT JWT)
    const passportJwt = responseVvpHeaders['P-VVP-Passport'];
    if (passportJwt) {
        const parsed = parseJWT(passportJwt);
        if (parsed) {
            html += renderJWTSection('PASSporT JWT (Response)', parsed, null, passportJwt);
        } else {
            html += '<div class="passport-error">P-VVP-Passport present but JWT is malformed</div>';
        }
    }

    // 3. P-VVP-Identity from request headers
    const pvvpValueReq = vvpHeaders['P-VVP-Identity'] || headers['P-VVP-Identity'];
    if (pvvpValueReq) {
        const pvvp = parsePVVPIdentity(pvvpValueReq);
        if (pvvp) {
            html += renderPVVPSection('P-VVP-Identity (Request)', pvvp);
        } else {
            html += '<div class="passport-error">P-VVP-Identity (request) present but failed to decode</div>';
        }
    }

    // 4. P-VVP-Identity from response headers
    const pvvpValueResp = responseVvpHeaders['P-VVP-Identity'];
    if (pvvpValueResp && pvvpValueResp !== pvvpValueReq) {
        const pvvp = parsePVVPIdentity(pvvpValueResp);
        if (pvvp) {
            html += renderPVVPSection('P-VVP-Identity (Response)', pvvp);
        } else {
            html += '<div class="passport-error">P-VVP-Identity (response) present but failed to decode</div>';
        }
    }

    // 5. No PASSporT data found anywhere
    if (!html) {
        html = '<p class="empty-message">No PASSporT or VVP identity headers found</p>';
    }

    return html;
}

/**
 * Render decoded JWT section with VVP field highlighting
 */
function renderJWTSection(title, parsed, params, rawJwt) {
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

    // VVP Explorer deep-link
    if (parsed.isVVP && rawJwt) {
        html += renderExplorerButton(rawJwt);
    }

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
        const response = await apiRequest('api/clear', { method: 'POST' });
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
        await apiRequest('api/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout error:', error);
    }
    window.location.href = 'login';
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
