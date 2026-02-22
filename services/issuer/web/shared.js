/**
 * VVP Issuer - Shared JavaScript Utilities
 */

// =============================================================================
// Navigation
// =============================================================================

/**
 * Shared navigation links — single source of truth for all pages.
 * To add a nav item, add an entry here. All pages pick it up automatically.
 */
const NAV_LINKS = [
  { href: '/ui/identity',    label: 'Identities' },
  { href: '/ui/schemas',     label: 'Schemas' },
  { href: '/ui/credentials', label: 'Credentials' },
  { href: '/ui/dossier',     label: 'Dossiers' },
  { href: '/ui/vvp',         label: 'VVP Headers' },
  { href: '/ui/tn-mappings', label: 'TN Mappings' },
  { href: '/ui/pbx',         label: 'PBX' },
  { href: '/ui/admin',       label: 'Admin' },
  { href: '/ui/vetter',     label: 'Vetter Certs', hidden: true },
  { href: '/organizations/ui', label: 'Organizations', hidden: true },
  { href: '/users/ui',       label: 'Users', hidden: true },
];

/**
 * Build navigation links from the shared NAV_LINKS array.
 * Replaces any existing nav content and marks the active link.
 * Should be called on DOMContentLoaded.
 */
function buildNavigation() {
  const nav = document.querySelector('.nav-links');
  if (!nav) return;
  nav.innerHTML = '';
  const currentPath = window.location.pathname;
  NAV_LINKS.forEach(item => {
    const a = document.createElement('a');
    a.href = item.href;
    a.textContent = item.label;
    if (item.hidden) a.style.display = 'none';
    if (item.external) a.target = '_blank';
    if (item.className) a.classList.add(item.className);
    if (item.href === currentPath) a.classList.add('active');
    nav.appendChild(a);
  });

  // Add hamburger toggle for mobile (inserted before .nav-links)
  const header = document.querySelector('.site-header');
  if (header && !document.getElementById('hamburger-btn')) {
    const btn = document.createElement('button');
    btn.id = 'hamburger-btn';
    btn.className = 'hamburger-btn';
    btn.setAttribute('aria-label', 'Toggle navigation');
    btn.innerHTML = '☰';
    btn.addEventListener('click', () => {
      header.classList.toggle('nav-open');
    });
    // Insert before .nav-links
    header.insertBefore(btn, nav);
  }
}

/**
 * Build the header utility area with help dropdown and Verifier link.
 * Inserted after the auth-status container in the header.
 */
function buildHeaderUtility() {
  const header = document.querySelector('.site-header');
  if (!header || document.getElementById('header-utility')) return;

  const utility = document.createElement('div');
  utility.id = 'header-utility';
  utility.className = 'header-utility';

  // --- Help dropdown ---
  const helpWrap = document.createElement('div');
  helpWrap.className = 'help-dropdown-wrap';

  const helpBtn = document.createElement('button');
  helpBtn.className = 'help-trigger';
  helpBtn.setAttribute('aria-label', 'Help menu');
  helpBtn.textContent = '?';
  helpBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    helpWrap.classList.toggle('open');
  });

  const dropdown = document.createElement('div');
  dropdown.className = 'help-dropdown';

  const quickRef = document.createElement('a');
  quickRef.href = '#';
  quickRef.textContent = 'Quick Reference';
  quickRef.addEventListener('click', (e) => {
    e.preventDefault();
    helpWrap.classList.remove('open');
    showIssuerHelp();
  });

  const helpGuide = document.createElement('a');
  helpGuide.href = '/ui/help';
  helpGuide.textContent = 'Help Guide';

  dropdown.appendChild(quickRef);
  dropdown.appendChild(helpGuide);
  helpWrap.appendChild(helpBtn);
  helpWrap.appendChild(dropdown);
  utility.appendChild(helpWrap);

  // --- Verifier external link ---
  const verifierLink = document.createElement('a');
  verifierLink.href = 'https://vvp-verifier.rcnx.io';
  verifierLink.target = '_blank';
  verifierLink.rel = 'noopener';
  verifierLink.className = 'verifier-ext-link';
  verifierLink.innerHTML = 'Verifier <span class="ext-icon">↗</span>';
  utility.appendChild(verifierLink);

  header.appendChild(utility);

  // Close help dropdown when clicking elsewhere
  document.addEventListener('click', () => {
    helpWrap.classList.remove('open');
  });
}

// =============================================================================
// Clipboard
// =============================================================================

/**
 * Copy text to clipboard and provide visual feedback on button.
 * @param {string} text - Text to copy
 * @param {HTMLElement} btn - Button element to show feedback on
 */
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('success');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('success');
    }, 1500);
  }).catch(err => {
    console.error('Failed to copy:', err);
    btn.textContent = 'Failed';
    setTimeout(() => {
      btn.textContent = 'Copy';
    }, 1500);
  });
}

// =============================================================================
// Modal
// =============================================================================

/**
 * Create and show a modal dialog.
 * @param {string} content - HTML content for the modal
 * @param {Object} options - Options for the modal
 * @param {string} options.title - Optional title
 * @param {Function} options.onClose - Optional callback when modal closes
 * @returns {HTMLElement} The modal overlay element
 */
function showModal(content, options = {}) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';

  let html = '<div class="modal">';
  if (options.title) {
    html += `<h3>${escapeHtml(options.title)}</h3>`;
  }
  html += content;
  html += `<button onclick="closeModal(this)" style="margin-top:1rem;" class="secondary">Close</button>`;
  html += '</div>';

  overlay.innerHTML = html;

  // Close on overlay click
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) {
      overlay.remove();
      if (options.onClose) options.onClose();
    }
  });

  // Close on Escape key
  const escHandler = (e) => {
    if (e.key === 'Escape') {
      overlay.remove();
      document.removeEventListener('keydown', escHandler);
      if (options.onClose) options.onClose();
    }
  };
  document.addEventListener('keydown', escHandler);

  document.body.appendChild(overlay);
  return overlay;
}

/**
 * Close a modal by finding its overlay parent.
 * @param {HTMLElement} element - Any element inside the modal
 */
function closeModal(element) {
  const overlay = element.closest('.modal-overlay');
  if (overlay) {
    overlay.remove();
  }
}

// =============================================================================
// API Helpers
// =============================================================================

/**
 * Make an API request with standard error handling.
 * @param {string} url - API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise<Object>} Response data
 * @throws {Error} If request fails
 */
async function apiRequest(url, options = {}) {
  const defaultOptions = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const mergedOptions = {
    ...defaultOptions,
    ...options,
    headers: {
      ...defaultOptions.headers,
      ...options.headers,
    },
  };

  const response = await fetch(url, mergedOptions);
  const data = await response.json();

  if (!response.ok) {
    const error = new Error(data.detail || data.message || 'Request failed');
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

/**
 * POST JSON data to an API endpoint.
 * @param {string} url - API endpoint
 * @param {Object} body - Request body
 * @returns {Promise<Object>} Response data
 */
async function apiPost(url, body) {
  return apiRequest(url, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * GET from an API endpoint.
 * @param {string} url - API endpoint
 * @returns {Promise<Object>} Response data
 */
async function apiGet(url) {
  return apiRequest(url, {
    method: 'GET',
  });
}

/**
 * DELETE to an API endpoint.
 * @param {string} url - API endpoint
 * @returns {Promise<Object>} Response data
 */
async function apiDelete(url) {
  return apiRequest(url, {
    method: 'DELETE',
  });
}

// =============================================================================
// Session Authentication
// =============================================================================

/**
 * Current session state, populated by checkAuthStatus().
 * Sprint 41: Added organization_id and organization_name for multi-tenancy.
 */
let currentSession = {
  authenticated: false,
  method: null,
  keyId: null,
  name: null,
  roles: [],
  expiresAt: null,
  organizationId: null,
  organizationName: null,
  // Sprint 67: Org context switching
  homeOrgId: null,
  homeOrgName: null,
  homeOrgType: null,
  activeOrgId: null,
  activeOrgName: null,
  activeOrgType: null,
};

/**
 * Single-flight guard for login modal.
 * Prevents multiple concurrent login prompts.
 */
let loginModalPromise = null;

/**
 * Check current authentication status from the server.
 * Updates currentSession state including organization context.
 * @returns {Promise<Object>} Auth status
 */
async function checkAuthStatus() {
  try {
    const response = await fetch('/auth/status');
    if (response.ok) {
      const data = await response.json();
      currentSession = {
        authenticated: data.authenticated,
        method: data.method,
        keyId: data.key_id,
        name: data.name,
        roles: data.roles || [],
        expiresAt: data.expires_at,
        organizationId: data.organization_id || null,
        organizationName: data.organization_name || null,
        // Sprint 67: Org context switching
        homeOrgId: data.home_org_id || null,
        homeOrgName: data.home_org_name || null,
        homeOrgType: data.home_org_type || null,
        activeOrgId: data.active_org_id || null,
        activeOrgName: data.active_org_name || null,
        activeOrgType: data.active_org_type || null,
      };
    }
  } catch (err) {
    console.error('Failed to check auth status:', err);
  }
  return currentSession;
}

/**
 * Check OAuth provider status from server.
 * @returns {Promise<Object|null>} OAuth status or null on error
 */
async function checkOAuthStatus() {
  try {
    const response = await fetch('/auth/oauth/status');
    if (response.ok) {
      return await response.json();
    }
  } catch (err) {
    console.error('Failed to check OAuth status:', err);
  }
  return null;
}

/**
 * Handle OAuth error from URL query parameters.
 * Called on page load to show error toast if OAuth failed.
 */
function handleOAuthError() {
  const params = new URLSearchParams(window.location.search);
  const error = params.get('error');
  const message = params.get('message');

  if (error === 'oauth_failed') {
    showToast(message || 'OAuth authentication failed', 'error');
    // Clean up URL
    const url = new URL(window.location);
    url.searchParams.delete('error');
    url.searchParams.delete('message');
    window.history.replaceState({}, '', url);
  }
}

/**
 * Redirect to Microsoft OAuth login.
 */
function startMicrosoftLogin() {
  const currentPath = window.location.pathname;
  window.location.href = `/auth/oauth/m365/start?redirect_after=${encodeURIComponent(currentPath)}`;
}

/**
 * Show login modal and return promise that resolves when logged in.
 * Uses single-flight pattern to prevent multiple concurrent modals.
 * Supports email/password, API key, and Microsoft OAuth authentication.
 * @returns {Promise<boolean>} True if login successful, false if cancelled
 */
function showLoginModal() {
  // Reuse existing modal if already showing
  if (loginModalPromise) {
    return loginModalPromise;
  }

  loginModalPromise = new Promise((resolve) => {
    const html = `
      <div class="login-form">
        <!-- Microsoft Sign-In Button (shown only if OAuth enabled) -->
        <div class="oauth-buttons" id="oauth-buttons" style="display: none;">
          <button class="oauth-btn oauth-microsoft" id="oauth-microsoft-btn" type="button">
            <svg class="oauth-icon" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg">
              <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
              <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
              <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
              <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
            </svg>
            Sign in with Microsoft
          </button>
          <div class="oauth-divider"><span>or</span></div>
        </div>

        <div class="login-tabs">
          <button class="login-tab active" data-tab="user">Email/Password</button>
          <button class="login-tab" data-tab="apikey">API Key</button>
        </div>

        <div class="login-tab-content active" id="login-tab-user">
          <div class="login-field">
            <label for="login-email">Email</label>
            <input type="email" id="login-email" placeholder="Enter your email" autocomplete="email">
          </div>
          <div class="login-field">
            <label for="login-password">Password</label>
            <input type="password" id="login-password" placeholder="Enter your password" autocomplete="current-password">
          </div>
        </div>

        <div class="login-tab-content" id="login-tab-apikey">
          <div class="login-field">
            <label for="login-api-key">API Key</label>
            <input type="password" id="login-api-key" placeholder="Enter your API key" autocomplete="off">
          </div>
        </div>

        <div id="login-error" class="error" style="display: none;"></div>
        <div class="login-buttons">
          <button id="login-submit" class="primary">Login</button>
          <button id="login-cancel" class="secondary">Cancel</button>
        </div>
      </div>
    `;

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay login-modal-overlay';

    let modalHtml = '<div class="modal login-modal">';
    modalHtml += '<h3>Authentication Required</h3>';
    modalHtml += html;
    modalHtml += '</div>';

    overlay.innerHTML = modalHtml;

    // Check OAuth status and show Microsoft button if enabled
    checkOAuthStatus().then(oauthStatus => {
      if (oauthStatus?.m365?.enabled) {
        const oauthButtons = overlay.querySelector('#oauth-buttons');
        if (oauthButtons) {
          oauthButtons.style.display = 'block';
        }
        const msBtn = overlay.querySelector('#oauth-microsoft-btn');
        if (msBtn) {
          msBtn.onclick = () => {
            startMicrosoftLogin();
          };
        }
      }
    });

    // Store resolve function for handlers
    overlay._loginResolve = resolve;
    overlay._loginTab = 'user';  // Default to email/password

    // Handle tab switching
    overlay.querySelectorAll('.login-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const tabName = tab.dataset.tab;
        overlay._loginTab = tabName;

        // Update tab buttons
        overlay.querySelectorAll('.login-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        // Update tab content
        overlay.querySelectorAll('.login-tab-content').forEach(c => c.classList.remove('active'));
        overlay.querySelector(`#login-tab-${tabName}`).classList.add('active');

        // Focus appropriate input
        if (tabName === 'user') {
          overlay.querySelector('#login-email').focus();
        } else {
          overlay.querySelector('#login-api-key').focus();
        }
      });
    });

    // Handle cancel button
    overlay.querySelector('#login-cancel').onclick = () => {
      overlay.remove();
      loginModalPromise = null;
      resolve(false);
    };

    // Handle submit button
    overlay.querySelector('#login-submit').onclick = () => submitLoginFromModal(overlay);

    // Handle Enter key in inputs
    overlay.querySelectorAll('input').forEach(input => {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          submitLoginFromModal(overlay);
        }
      });
    });

    // Handle Escape key
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        overlay.remove();
        document.removeEventListener('keydown', escHandler);
        loginModalPromise = null;
        resolve(false);
      }
    };
    document.addEventListener('keydown', escHandler);
    overlay._escHandler = escHandler;

    // Handle overlay click (close on background click)
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.remove();
        document.removeEventListener('keydown', overlay._escHandler);
        loginModalPromise = null;
        resolve(false);
      }
    });

    document.body.appendChild(overlay);

    // Focus email input after a short delay (for animation)
    setTimeout(() => {
      const input = document.getElementById('login-email');
      if (input) input.focus();
    }, 100);
  }).finally(() => {
    loginModalPromise = null;
  });

  return loginModalPromise;
}

/**
 * Submit login from modal.
 * Handles both email/password and API key authentication.
 * @param {HTMLElement} overlay - The modal overlay element
 */
async function submitLoginFromModal(overlay) {
  const errorEl = overlay.querySelector('#login-error');
  const submitBtn = overlay.querySelector('#login-submit');
  const resolve = overlay._loginResolve;
  const loginTab = overlay._loginTab || 'user';

  let body = {};

  if (loginTab === 'user') {
    // Email/password login
    const email = overlay.querySelector('#login-email')?.value?.trim();
    const password = overlay.querySelector('#login-password')?.value;

    if (!email) {
      errorEl.textContent = 'Email is required';
      errorEl.style.display = 'block';
      return;
    }
    if (!password) {
      errorEl.textContent = 'Password is required';
      errorEl.style.display = 'block';
      return;
    }

    body = { email, password };
  } else {
    // API key login
    const apiKey = overlay.querySelector('#login-api-key')?.value?.trim();

    if (!apiKey) {
      errorEl.textContent = 'API key is required';
      errorEl.style.display = 'block';
      return;
    }

    body = { api_key: apiKey };
  }

  setButtonLoading(submitBtn, 'Logging in...');
  errorEl.style.display = 'none';

  try {
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const result = await response.json();

    if (response.status === 429) {
      // Rate limited
      errorEl.textContent = result.error || 'Too many attempts. Please try again later.';
      errorEl.style.display = 'block';
      resetButton(submitBtn);
      return;
    }

    if (result.success) {
      currentSession = {
        authenticated: true,
        method: 'session',
        keyId: result.key_id,
        name: result.name,
        roles: result.roles || [],
        expiresAt: result.expires_at,
        organizationId: result.organization_id || null,
        organizationName: result.organization_name || null,
      };

      // Clean up and resolve
      if (overlay._escHandler) {
        document.removeEventListener('keydown', overlay._escHandler);
      }
      overlay.remove();
      showToast(`Logged in as ${result.name}`, 'success');
      updateAuthUI();
      resolve?.(true);
    } else {
      const errorMsg = loginTab === 'user' ? 'Invalid email or password' : 'Invalid API key';
      errorEl.textContent = errorMsg;
      errorEl.style.display = 'block';
      resetButton(submitBtn);
    }
  } catch (err) {
    errorEl.textContent = 'Login failed: ' + err.message;
    errorEl.style.display = 'block';
    resetButton(submitBtn);
  }
}

/**
 * Logout and clear session.
 */
async function logout() {
  try {
    await fetch('/auth/logout', { method: 'POST' });
    currentSession = {
      authenticated: false,
      method: null,
      keyId: null,
      name: null,
      roles: [],
      expiresAt: null,
      organizationId: null,
      organizationName: null,
    };
    showToast('Logged out', 'info');
    updateAuthUI();
  } catch (err) {
    console.error('Logout failed:', err);
  }
}

/**
 * Update UI elements to reflect auth state.
 * Sprint 41: Shows organization context in the header.
 */
function updateAuthUI() {
  const authStatus = document.getElementById('auth-status');
  if (authStatus) {
    if (currentSession.authenticated) {
      let userInfo = escapeHtml(currentSession.name || currentSession.keyId);
      if (currentSession.organizationName) {
        userInfo += ` <span class="auth-org">| ${escapeHtml(currentSession.organizationName)}</span>`;
      }
      // Sprint 67: Show org switcher badge for admins with active org
      let orgSwitcherHtml = '';
      if (currentSession.roles.includes('issuer:admin')) {
        if (currentSession.activeOrgId) {
          orgSwitcherHtml = `
            <button onclick="showOrgSwitcher()" class="small secondary org-switch-btn" title="Acting as ${escapeHtml(currentSession.activeOrgName || '')}">
              Acting as: ${escapeHtml(currentSession.activeOrgName || 'Unknown')}
            </button>
            <button onclick="revertOrgContext()" class="small secondary" title="Revert to home org">x</button>
          `;
        } else {
          orgSwitcherHtml = `
            <button onclick="showOrgSwitcher()" class="small secondary org-switch-btn" title="Switch org context">Switch Org</button>
          `;
        }
      }
      authStatus.innerHTML = `
        <span class="auth-user">${userInfo}</span>
        ${orgSwitcherHtml}
        <a href="/profile" class="small secondary" style="margin-right:0.5rem">Profile</a>
        <button onclick="logout()" class="small secondary">Logout</button>
      `;
    } else {
      authStatus.innerHTML = `
        <button onclick="showLoginModal()" class="small primary">Login</button>
      `;
    }
  }

  // Update role-based navigation visibility
  updateNavVisibility();
}

/**
 * Sprint 67: Show org switcher modal for admins.
 * Fetches all orgs and lets admin select one to act as.
 */
async function showOrgSwitcher() {
  try {
    const response = await authFetch('/organizations');
    if (!response.ok) {
      showToast('Failed to load organizations', 'error');
      return;
    }
    const data = await response.json();
    const orgs = data.organizations || [];

    if (orgs.length === 0) {
      showToast('No organizations available', 'warning');
      return;
    }

    // Build org list HTML
    const orgItems = orgs.map(org => {
      const isCurrent = org.id === currentSession.activeOrgId ||
                        (!currentSession.activeOrgId && org.id === currentSession.homeOrgId);
      const typeBadge = org.org_type && org.org_type !== 'regular'
        ? `<span class="badge badge-${org.org_type}">${org.org_type}</span>`
        : '';
      return `
        <div class="org-switch-item ${isCurrent ? 'current' : ''}"
             onclick="switchOrgContext('${org.id}')" style="cursor:pointer; padding:0.5rem; border-bottom:1px solid var(--border);">
          <strong>${escapeHtml(org.name)}</strong> ${typeBadge}
          ${isCurrent ? '<span class="badge">current</span>' : ''}
        </div>
      `;
    }).join('');

    showModal(`
      <p style="margin-bottom:0.5rem">Select an organization to act on behalf of:</p>
      <div style="max-height:300px; overflow-y:auto; border:1px solid var(--border); border-radius:4px;">
        ${orgItems}
      </div>
      <div style="margin-top:0.75rem">
        <button onclick="revertOrgContext()" class="small secondary">Revert to Home Org</button>
      </div>
    `, { title: 'Switch Organization' });
  } catch (err) {
    showToast('Failed to load organizations: ' + err.message, 'error');
  }
}

/**
 * Sprint 67: Switch org context via POST /session/switch-org.
 * @param {string} orgId - Organization ID to switch to
 */
async function switchOrgContext(orgId) {
  try {
    const response = await authFetch('/session/switch-org', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ organization_id: orgId }),
    });
    if (response.ok) {
      const data = await response.json();
      showToast(`Switched to ${data.active_org_name || 'organization'}`, 'success');
      document.querySelector('.modal-overlay')?.remove();
      // Sprint 67 R5: Full page reload to refresh all org-scoped data
      // (schemas, registries, credential lists, etc.)
      window.location.reload();
    } else {
      const err = await response.json().catch(() => ({}));
      showToast(err.detail || 'Failed to switch organization', 'error');
    }
  } catch (err) {
    showToast('Failed to switch organization: ' + err.message, 'error');
  }
}

/**
 * Sprint 67: Revert to home org (clear active_org_id).
 */
async function revertOrgContext() {
  try {
    const response = await authFetch('/session/switch-org', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ organization_id: null }),
    });
    if (response.ok) {
      showToast('Reverted to home organization', 'success');
      document.querySelector('.modal-overlay')?.remove();
      // Sprint 67 R5: Full page reload to refresh all org-scoped data
      window.location.reload();
    } else {
      const err = await response.json().catch(() => ({}));
      showToast(err.detail || 'Failed to revert organization', 'error');
    }
  } catch (err) {
    showToast('Failed to revert organization: ' + err.message, 'error');
  }
}

/**
 * Update navigation link visibility based on user roles.
 * Sprint 41: Shows/hides Users and Organizations links based on permissions.
 */
function updateNavVisibility() {
  const isSystemAdmin = currentSession.roles.includes('issuer:admin');
  const isOrgAdmin = currentSession.roles.includes('org:administrator');

  // Users link - visible to system admins and org admins
  const usersLink = document.querySelector('a[href="/users/ui"]');
  if (usersLink) {
    usersLink.style.display = (isSystemAdmin || isOrgAdmin) ? '' : 'none';
  }

  // Organizations link - visible to system admins only
  const orgsLink = document.querySelector('a[href="/organizations/ui"]');
  if (orgsLink) {
    orgsLink.style.display = isSystemAdmin ? '' : 'none';
  }

  // Vetter Certs link - visible to system admins and vetter/root authority orgs
  const vetterLink = document.querySelector('a[href="/ui/vetter"]');
  if (vetterLink) {
    const isVetterOrg = currentSession.activeOrgType === 'vetter_authority'
                     || currentSession.activeOrgType === 'root_authority';
    vetterLink.style.display = (isSystemAdmin || isVetterOrg) ? '' : 'none';
  }
}

/**
 * Check if current user has a specific role.
 * @param {string} role - Role to check
 * @returns {boolean} True if user has the role
 */
function hasRole(role) {
  return currentSession.roles.includes(role);
}

/**
 * Check if current user is a system admin.
 * @returns {boolean} True if user has issuer:admin role
 */
function isSystemAdmin() {
  return hasRole('issuer:admin');
}

/**
 * Check if current user is an organization admin.
 * @returns {boolean} True if user has org:administrator role
 */
function isOrgAdmin() {
  return hasRole('org:administrator');
}

/**
 * Make an authenticated API request.
 * Shows login modal on 401, retries after successful login.
 * Includes CSRF header for cookie-authenticated requests.
 * @param {string} url - API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} Fetch response
 */
async function authFetch(url, options = {}) {
  const mergedOptions = {
    ...options,
    headers: {
      'X-Requested-With': 'XMLHttpRequest', // CSRF protection
      ...options.headers,
    },
  };

  const response = await fetch(url, mergedOptions);

  if (response.status === 401) {
    // Try to login
    const loggedIn = await showLoginModal();
    if (loggedIn) {
      // Retry the request with new session
      return authFetch(url, options);
    } else {
      // User cancelled login
      const error = new Error('Authentication required');
      error.status = 401;
      throw error;
    }
  }

  return response;
}

/**
 * Make an authenticated API request and parse JSON response.
 * @param {string} url - API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise<Object>} Response data
 */
async function authRequest(url, options = {}) {
  const defaultOptions = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const mergedOptions = {
    ...defaultOptions,
    ...options,
    headers: {
      ...defaultOptions.headers,
      ...options.headers,
    },
  };

  const response = await authFetch(url, mergedOptions);
  const data = await response.json();

  if (!response.ok) {
    const error = new Error(data.detail || data.message || 'Request failed');
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

/**
 * POST JSON data to an API endpoint with authentication.
 * @param {string} url - API endpoint
 * @param {Object} body - Request body
 * @returns {Promise<Object>} Response data
 */
async function authPost(url, body) {
  return authRequest(url, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * DELETE to an API endpoint with authentication.
 * @param {string} url - API endpoint
 * @returns {Promise<Object>} Response data
 */
async function authDelete(url) {
  return authRequest(url, {
    method: 'DELETE',
  });
}

// =============================================================================
// UI Helpers
// =============================================================================

/**
 * Escape HTML to prevent XSS.
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Format a label from camelCase or snake_case to Title Case.
 * @param {string} str - String to format
 * @returns {string} Formatted string
 */
function formatLabel(str) {
  return str
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/\b\w/g, c => c.toUpperCase());
}

/**
 * Format bytes to human-readable size.
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted size
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Show a loading state on a button.
 * @param {HTMLButtonElement} btn - Button element
 * @param {string} text - Loading text
 */
function setButtonLoading(btn, text = 'Loading...') {
  btn.disabled = true;
  btn.dataset.originalText = btn.textContent;
  btn.innerHTML = `<span class="spinner"></span>${text}`;
}

/**
 * Reset a button from loading state.
 * @param {HTMLButtonElement} btn - Button element
 */
function resetButton(btn) {
  btn.disabled = false;
  btn.textContent = btn.dataset.originalText || 'Submit';
}

/**
 * Show an error message in a container.
 * @param {HTMLElement} container - Container element
 * @param {string|Error} error - Error message or Error object
 */
function showError(container, error) {
  const message = error instanceof Error ? error.message : error;
  container.innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
}

/**
 * Show a success message in a container.
 * @param {HTMLElement} container - Container element
 * @param {string} message - Success message
 */
function showSuccess(container, message) {
  container.innerHTML = `<div class="success">${escapeHtml(message)}</div>`;
}

// =============================================================================
// Tabs
// =============================================================================

/**
 * Initialize tab functionality for a tab container.
 * @param {string} tabsSelector - CSS selector for tab buttons container
 * @param {string} panelsSelector - CSS selector for tab panels container
 */
function initTabs(tabsSelector, panelsSelector) {
  const tabs = document.querySelectorAll(`${tabsSelector} .tab`);
  const panels = document.querySelectorAll(`${panelsSelector} .tab-panel`);

  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => {
      // Remove active from all
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      // Add active to clicked
      tab.classList.add('active');
      if (panels[index]) {
        panels[index].classList.add('active');
      }
    });
  });
}

// =============================================================================
// Help Menu
// =============================================================================

/**
 * Help content for VVP Issuer service.
 */
const ISSUER_HELP_CONTENT = {
  title: 'VVP Issuer Help',
  sections: [
    {
      title: 'Identities',
      description: 'Create and manage KERI identities (AIDs) for credential issuance.',
      options: [
        { name: 'Create Identity', desc: 'Generate a new KERI identity with configurable key settings' },
        { name: 'View OOBI URLs', desc: 'Get shareable URLs for others to discover your identity' },
        { name: 'Rotate Keys', desc: 'Replace current signing keys with new ones (transferable identities only)' }
      ],
      link: '/ui/identity'
    },
    {
      title: 'Registries',
      description: 'Set up credential registries (TELs) to track issued credentials.',
      options: [
        { name: 'Create Registry', desc: 'Create a new Transaction Event Log for credential lifecycle tracking' },
        { name: 'No Backers Mode', desc: 'Simpler setup without TEL-specific witness backers' }
      ],
      link: '/ui/registry'
    },
    {
      title: 'Schemas',
      description: 'Manage credential schemas that define the structure of credentials.',
      options: [
        { name: 'Import from WebOfTrust', desc: 'Import standard schemas from the WebOfTrust/schema repository' },
        { name: 'Create Custom Schema', desc: 'Define your own credential schema with custom properties' },
        { name: 'Validate SAID', desc: 'Verify a schema SAID is recognized and valid' }
      ],
      link: '/ui/schemas'
    },
    {
      title: 'Credentials',
      description: 'Issue and manage ACDC verifiable credentials.',
      options: [
        { name: 'Issue Credential', desc: 'Create a new credential using a registry and schema' },
        { name: 'Form Mode', desc: 'Fill in credential attributes using an auto-generated form' },
        { name: 'JSON Mode', desc: 'Enter credential attributes as raw JSON for advanced use' },
        { name: 'Revoke Credential', desc: 'Mark a credential as revoked in the registry' }
      ],
      link: '/ui/credentials'
    },
    {
      title: 'Dossiers',
      description: 'Assemble credentials into portable dossiers for presentation.',
      options: [
        { name: 'Build Dossier', desc: 'Package credentials and their chain into a verifiable bundle' },
        { name: 'CESR Format', desc: 'Export as a CESR stream (compact binary format)' },
        { name: 'JSON Format', desc: 'Export as a JSON array for easier inspection' }
      ],
      link: '/ui/dossier'
    },
    {
      title: 'Admin',
      description: 'Service configuration and runtime controls.',
      options: [
        { name: 'Service Status', desc: 'View health, version, and statistics' },
        { name: 'Log Level', desc: 'Adjust logging verbosity at runtime' },
        { name: 'Reload Config', desc: 'Hot-reload API keys and witness configuration' }
      ],
      link: '/ui/admin'
    }
  ],
  tip: 'Start by creating an Identity, then a Registry, then issue Credentials using a Schema.'
};

/**
 * Show the help modal for the Issuer service.
 */
function showIssuerHelp() {
  const help = ISSUER_HELP_CONTENT;

  let html = `<div class="help-modal">`;
  html += `<h3>${escapeHtml(help.title)}</h3>`;

  for (const section of help.sections) {
    html += `<div class="help-section">`;
    html += `<h4><a href="${section.link}">${escapeHtml(section.title)}</a></h4>`;
    html += `<p>${escapeHtml(section.description)}</p>`;
    html += `<ul class="help-options">`;
    for (const opt of section.options) {
      html += `<li><strong>${escapeHtml(opt.name)}</strong><span>${escapeHtml(opt.desc)}</span></li>`;
    }
    html += `</ul></div>`;
  }

  if (help.tip) {
    html += `<div class="help-tip"><strong>Tip:</strong> ${escapeHtml(help.tip)}</div>`;
  }

  html += `</div>`;

  showModal(html, { title: null });
}

/**
 * Show a toast notification.
 * @param {string} message - Message to display
 * @param {string} type - Toast type (success, error, warning, info)
 */
function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    container.style.cssText = 'position:fixed;top:1rem;right:1rem;z-index:1100;';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.style.cssText = 'padding:1rem;margin-bottom:0.5rem;border-radius:4px;animation:fadeIn 0.3s ease-in;';

  if (type === 'success') toast.style.background = 'var(--vvp-success)';
  else if (type === 'error') toast.style.background = 'var(--vvp-danger)';
  else if (type === 'warning') { toast.style.background = 'var(--vvp-warning)'; toast.style.color = '#000'; }
  else toast.style.background = 'var(--vvp-info)';

  toast.style.color = type === 'warning' ? '#000' : '#fff';
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => toast.remove(), 5000);
}

// =============================================================================
// Initialize on DOM ready
// =============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  buildNavigation();

  // Handle OAuth errors from URL parameters (e.g., after failed OAuth callback)
  handleOAuthError();

  // Build utility area (help dropdown + Verifier link)
  buildHeaderUtility();

  // Add auth status container to header if it doesn't exist
  const header = document.querySelector('header');
  if (header && !document.getElementById('auth-status')) {
    const authStatus = document.createElement('div');
    authStatus.id = 'auth-status';
    authStatus.className = 'auth-status';
    // Insert auth-status inside utility area if it exists, otherwise append to header
    const utility = document.getElementById('header-utility');
    if (utility) {
      utility.appendChild(authStatus);
    } else {
      header.appendChild(authStatus);
    }
  }

  // Check auth status on page load
  await checkAuthStatus();
  updateAuthUI();
});
