/**
 * VVP Phone PWA — UI Controller
 *
 * Manages screen transitions, dial pad input, call overlay rendering,
 * status badges, and call duration timer.
 */

const UI = {

  // -----------------------------------------------------------------------
  // Screen Management
  // -----------------------------------------------------------------------

  /**
   * Show a screen by id, hiding all others.
   * @param {'login'|'dialer'} screenId
   */
  showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(el => el.classList.remove('active'));
    const target = document.getElementById(`screen-${screenId}`);
    if (target) target.classList.add('active');
  },

  /**
   * Update all UI elements based on the current call state.
   * @param {string} state - One of: disconnected, idle, ringing, calling, in_call
   * @param {Object} data  - Optional state-specific data (vvpData, number, etc.)
   */
  updateForState(state, data = {}) {
    switch (state) {
      case 'disconnected':
        this.showScreen('login');
        this.hideCallOverlay();
        this.stopDurationTimer();
        break;

      case 'idle':
        this.showScreen('dialer');
        this.hideCallOverlay();
        this.stopDurationTimer();
        this.clearDialInput();
        break;

      case 'ringing':
        this.showCallOverlay('ringing', data);
        break;

      case 'calling':
        this.showCallOverlay('calling', data);
        break;

      case 'in_call':
        this.showCallOverlay('in_call', data);
        this.startDurationTimer();
        break;
    }
  },


  // -----------------------------------------------------------------------
  // Call Overlay
  // -----------------------------------------------------------------------

  /**
   * Show the call overlay in a specific mode.
   * @param {'ringing'|'calling'|'in_call'} mode
   * @param {Object} data - { vvpData, number }
   */
  showCallOverlay(mode, data = {}) {
    const overlay = document.getElementById('call-overlay');
    const actions = document.getElementById('call-actions');
    const acceptBtn = document.getElementById('btn-accept');
    const durationEl = document.getElementById('call-duration');
    const labelEl = document.getElementById('call-label');

    // Reset classes
    overlay.className = 'call-overlay active';
    actions.className = 'call-actions';

    if (mode === 'ringing') {
      overlay.classList.add('ringing');
      acceptBtn.style.display = '';
      durationEl.style.display = 'none';
      labelEl.textContent = 'Incoming call';
    } else if (mode === 'calling') {
      acceptBtn.style.display = 'none';
      durationEl.style.display = 'none';
      labelEl.textContent = 'Calling\u2026';
    } else if (mode === 'in_call') {
      acceptBtn.style.display = 'none';
      actions.classList.add('in-call');
      durationEl.style.display = '';
      durationEl.textContent = '00:00';
      labelEl.textContent = 'Connected';
    }

    // Populate VVP data
    if (data.vvpData) {
      this.renderVVPData(data.vvpData);
    }
    if (data.number) {
      document.getElementById('call-number').textContent = data.number;
    }
  },

  hideCallOverlay() {
    const overlay = document.getElementById('call-overlay');
    overlay.className = 'call-overlay';
  },

  /**
   * Render VVP brand/status data into the call overlay.
   * @param {Object} vvpData - From VVPDisplay.extractFromSIPSession()
   */
  renderVVPData(vvpData) {
    // Avatar / logo
    const logoEl = document.getElementById('call-logo');
    logoEl.src = vvpData.brand_logo || VVPDisplay.placeholderLogo;
    logoEl.onerror = () => { logoEl.src = VVPDisplay.placeholderLogo; };

    // Brand name
    document.getElementById('call-brand-name').textContent = vvpData.brand_name;

    // Status badge
    const statusBadge = document.getElementById('call-status-badge');
    const cfg = VVPDisplay.statusConfig[vvpData.status] || VVPDisplay.statusConfig.UNKNOWN;
    statusBadge.className = `call-status-badge ${cfg.className}`;
    statusBadge.innerHTML = `<span class="badge-icon">${cfg.icon}</span> ${cfg.label}`;

    // Vetter badge
    const vetterBadge = document.getElementById('call-vetter-badge');
    if (vvpData.vetter_status && VVPDisplay.vetterStatusConfig[vvpData.vetter_status]) {
      const vcfg = VVPDisplay.vetterStatusConfig[vvpData.vetter_status];
      vetterBadge.className = `call-vetter-badge ${vcfg.className}`;
      vetterBadge.textContent = vcfg.label;
      vetterBadge.style.display = '';
    } else {
      vetterBadge.style.display = 'none';
    }

    // Caller number
    if (vvpData.caller_number) {
      document.getElementById('call-number').textContent = vvpData.caller_number;
    }
  },


  // -----------------------------------------------------------------------
  // Call Duration Timer
  // -----------------------------------------------------------------------

  _timerInterval: null,
  _timerStart: 0,

  startDurationTimer() {
    this.stopDurationTimer();
    this._timerStart = Date.now();
    const el = document.getElementById('call-duration');
    this._timerInterval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - this._timerStart) / 1000);
      const min = String(Math.floor(elapsed / 60)).padStart(2, '0');
      const sec = String(elapsed % 60).padStart(2, '0');
      el.textContent = `${min}:${sec}`;
    }, 1000);
  },

  stopDurationTimer() {
    if (this._timerInterval) {
      clearInterval(this._timerInterval);
      this._timerInterval = null;
    }
  },


  // -----------------------------------------------------------------------
  // Dial Pad
  // -----------------------------------------------------------------------

  /**
   * Initialize dial pad key handlers.
   */
  initDialPad() {
    document.querySelectorAll('.dial-key').forEach(key => {
      key.addEventListener('click', () => {
        const digit = key.dataset.digit;
        if (digit == null) return;
        this.appendDigit(digit);
        // Haptic feedback
        if (navigator.vibrate) navigator.vibrate(10);
      });
    });

    // Backspace
    const backspace = document.getElementById('btn-backspace');
    if (backspace) {
      backspace.addEventListener('click', () => this.deleteDigit());
      // Long-press to clear
      let pressTimer;
      backspace.addEventListener('touchstart', (e) => {
        pressTimer = setTimeout(() => this.clearDialInput(), 600);
      }, { passive: true });
      backspace.addEventListener('touchend', () => clearTimeout(pressTimer));
      backspace.addEventListener('touchcancel', () => clearTimeout(pressTimer));
    }

    // Quick dial chips
    document.querySelectorAll('.quick-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const number = chip.dataset.number;
        if (number) {
          const input = document.getElementById('dial-input');
          input.value = number;
        }
      });
    });
  },

  appendDigit(digit) {
    const input = document.getElementById('dial-input');
    input.value += digit;
  },

  deleteDigit() {
    const input = document.getElementById('dial-input');
    input.value = input.value.slice(0, -1);
  },

  clearDialInput() {
    document.getElementById('dial-input').value = '';
  },

  getDialValue() {
    return document.getElementById('dial-input').value.trim();
  },


  // -----------------------------------------------------------------------
  // Connection Indicator
  // -----------------------------------------------------------------------

  setConnectionStatus(status) {
    const indicator = document.getElementById('connection-indicator');
    const statusText = document.getElementById('status-text');
    if (indicator) {
      indicator.className = `indicator ${status}`;
    }
    if (statusText) {
      const labels = {
        connected: 'Ready',
        connecting: 'Connecting\u2026',
        disconnected: 'Disconnected',
      };
      statusText.textContent = labels[status] || status;
    }
  },

  setExtensionLabel(ext) {
    const el = document.getElementById('ext-display');
    if (el) el.textContent = `Ext ${ext}`;
  },

  /**
   * Show an error on the login screen.
   */
  showLoginError(message) {
    const el = document.getElementById('login-error');
    if (el) {
      el.textContent = message;
      el.classList.add('active');
    }
  },

  hideLoginError() {
    const el = document.getElementById('login-error');
    if (el) el.classList.remove('active');
  },
};
