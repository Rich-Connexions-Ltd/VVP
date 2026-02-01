/**
 * VVP Issuer - Shared JavaScript Utilities
 */

// =============================================================================
// Navigation
// =============================================================================

/**
 * Initialize navigation by marking the active link based on current URL path.
 * Should be called on DOMContentLoaded.
 */
function initNavigation() {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-links a').forEach(link => {
    const href = link.getAttribute('href');
    if (href === path) {
      link.classList.add('active');
    }
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
 */
let currentSession = {
  authenticated: false,
  method: null,
  keyId: null,
  name: null,
  roles: [],
  expiresAt: null,
};

/**
 * Single-flight guard for login modal.
 * Prevents multiple concurrent login prompts.
 */
let loginModalPromise = null;

/**
 * Check current authentication status from the server.
 * Updates currentSession state.
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
      };
    }
  } catch (err) {
    console.error('Failed to check auth status:', err);
  }
  return currentSession;
}

/**
 * Show login modal and return promise that resolves when logged in.
 * Uses single-flight pattern to prevent multiple concurrent modals.
 * Supports both email/password and API key authentication.
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
    };
    showToast('Logged out', 'info');
    updateAuthUI();
  } catch (err) {
    console.error('Logout failed:', err);
  }
}

/**
 * Update UI elements to reflect auth state.
 */
function updateAuthUI() {
  const authStatus = document.getElementById('auth-status');
  if (authStatus) {
    if (currentSession.authenticated) {
      authStatus.innerHTML = `
        <span class="auth-user">${escapeHtml(currentSession.name || currentSession.keyId)}</span>
        <button onclick="logout()" class="small secondary">Logout</button>
      `;
    } else {
      authStatus.innerHTML = `
        <button onclick="showLoginModal()" class="small primary">Login</button>
      `;
    }
  }
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
  initNavigation();

  // Add help button to header nav if it doesn't exist
  const nav = document.querySelector('.nav-links');
  if (nav && !document.getElementById('help-btn')) {
    const helpBtn = document.createElement('button');
    helpBtn.id = 'help-btn';
    helpBtn.className = 'help-btn';
    helpBtn.innerHTML = '? Help';
    helpBtn.onclick = showIssuerHelp;
    nav.appendChild(helpBtn);
  }

  // Add auth status container to header if it doesn't exist
  const header = document.querySelector('header');
  if (header && !document.getElementById('auth-status')) {
    const authStatus = document.createElement('div');
    authStatus.id = 'auth-status';
    authStatus.className = 'auth-status';
    header.appendChild(authStatus);
  }

  // Check auth status on page load
  await checkAuthStatus();
  updateAuthUI();
});
