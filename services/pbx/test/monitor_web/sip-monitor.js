/**
 * VVP SIP Monitor Dashboard - Client JavaScript
 * Sprint 47: Core client logic for event display and polling
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
        updateConnectionStatus('connected');

    } catch (error) {
        console.error('Failed to refresh events:', error);
        updateConnectionStatus('error');
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

        updateConnectionStatus('connected');

    } catch (error) {
        console.error('Polling error:', error);
        updateConnectionStatus('error');
    } finally {
        state.isPolling = false;
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

    el.classList.remove('status-connected', 'status-disconnected', 'status-error');

    switch (status) {
        case 'connected':
            el.classList.add('status-connected');
            el.textContent = 'Connected';
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

    // Start polling every 2 seconds
    state.pollingInterval = setInterval(pollEvents, 2000);

    console.log('VVP SIP Monitor initialized');
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
