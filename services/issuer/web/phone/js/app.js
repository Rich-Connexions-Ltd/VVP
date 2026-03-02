/**
 * VVP Phone PWA — SIP Application Logic
 *
 * Manages the SIP.js 0.15.x UserAgent lifecycle, call state machine,
 * localStorage credential persistence, and audio setup.
 */

// =========================================================================
// Constants
// =========================================================================

const DEFAULT_SERVER = 'wss://pbx.rcnx.io:7443';
const STORAGE_PREFIX = 'vvp-phone';
const RECONNECT_MAX_DELAY = 30000;
const RECONNECT_MAX_RETRIES = 10;

const CallState = {
  DISCONNECTED: 'disconnected',
  IDLE:         'idle',
  RINGING:      'ringing',
  CALLING:      'calling',
  IN_CALL:      'in_call',
};


// =========================================================================
// State
// =========================================================================

let state = CallState.DISCONNECTED;
let ua = null;
let currentSession = null;
let currentExtension = null;
let reconnectAttempts = 0;
let reconnectTimer = null;


// =========================================================================
// State Machine
// =========================================================================

function transition(newState, data = {}) {
  const prev = state;
  state = newState;
  console.log(`[VVP Phone] ${prev} -> ${newState}`);
  UI.updateForState(newState, data);
}


// =========================================================================
// localStorage Persistence
// =========================================================================

function storageKey(ext, key) {
  return `${STORAGE_PREFIX}-${ext}-${key}`;
}

function saveCredentials(ext, password) {
  localStorage.setItem(storageKey(ext, 'extension'), ext);
  localStorage.setItem(storageKey(ext, 'password'), password);
  localStorage.setItem(storageKey(ext, 'server'), DEFAULT_SERVER);
  localStorage.setItem(`${STORAGE_PREFIX}-last-ext`, ext);
}

function clearCredentials(ext) {
  localStorage.removeItem(storageKey(ext, 'extension'));
  localStorage.removeItem(storageKey(ext, 'password'));
  localStorage.removeItem(storageKey(ext, 'server'));
  localStorage.removeItem(`${STORAGE_PREFIX}-last-ext`);
}

function getSavedCredentials() {
  const lastExt = localStorage.getItem(`${STORAGE_PREFIX}-last-ext`);
  if (!lastExt) return null;
  const ext = localStorage.getItem(storageKey(lastExt, 'extension'));
  const password = localStorage.getItem(storageKey(lastExt, 'password'));
  if (!ext || !password) return null;
  return { extension: ext, password, server: DEFAULT_SERVER };
}


// =========================================================================
// SIP Connection
// =========================================================================

function connect(extension, password) {
  if (ua) {
    try { ua.stop(); } catch (_) { /* ignore */ }
    ua = null;
  }

  currentExtension = extension;
  UI.setExtensionLabel(extension);
  UI.setConnectionStatus('connecting');
  UI.hideLoginError();
  reconnectAttempts = 0;

  const serverUrl = new URL(DEFAULT_SERVER);
  const domain = serverUrl.hostname;

  try {
    ua = new SIP.UA({
      uri: `sip:${extension}@${domain}`,
      transportOptions: {
        wsServers: [DEFAULT_SERVER],
        traceSip: false,
      },
      authorizationUser: extension,
      password: password,
      register: true,
      sessionDescriptionHandlerFactoryOptions: {
        constraints: { audio: true, video: false },
      },
    });

    // Transport events
    ua.on('transportCreated', (transport) => {
      transport.on('connected', () => {
        console.log('[VVP Phone] WebSocket connected');
        reconnectAttempts = 0;
      });
      transport.on('disconnected', () => {
        console.log('[VVP Phone] WebSocket disconnected');
        if (state !== CallState.DISCONNECTED) {
          UI.setConnectionStatus('disconnected');
          scheduleReconnect(extension, password);
        }
      });
    });

    // Registration events
    ua.on('registered', () => {
      console.log('[VVP Phone] Registered');
      UI.setConnectionStatus('connected');
      transition(CallState.IDLE);
    });

    ua.on('unregistered', () => {
      console.log('[VVP Phone] Unregistered');
    });

    ua.on('registrationFailed', (_response, cause) => {
      console.error('[VVP Phone] Registration failed:', cause);
      UI.setConnectionStatus('disconnected');
      UI.showLoginError(`Registration failed: ${cause || 'unknown error'}`);
      transition(CallState.DISCONNECTED);
    });

    // Incoming call
    ua.on('invite', (session) => handleIncomingCall(session));

    ua.start();
  } catch (e) {
    console.error('[VVP Phone] Connection error:', e);
    UI.showLoginError(`Connection error: ${e.message}`);
    transition(CallState.DISCONNECTED);
  }
}

function disconnect() {
  clearReconnect();
  if (currentSession) {
    try { currentSession.terminate(); } catch (_) { /* ignore */ }
    currentSession = null;
  }
  if (ua) {
    try { ua.stop(); } catch (_) { /* ignore */ }
    ua = null;
  }
  if (currentExtension) {
    clearCredentials(currentExtension);
  }
  currentExtension = null;
  transition(CallState.DISCONNECTED);
}


// =========================================================================
// Reconnection
// =========================================================================

function scheduleReconnect(extension, password) {
  clearReconnect();
  if (reconnectAttempts >= RECONNECT_MAX_RETRIES) {
    console.log('[VVP Phone] Max reconnect attempts reached');
    transition(CallState.DISCONNECTED);
    UI.showLoginError('Connection lost. Please reconnect.');
    return;
  }
  const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), RECONNECT_MAX_DELAY);
  reconnectAttempts++;
  console.log(`[VVP Phone] Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => connect(extension, password), delay);
}

function clearReconnect() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}


// =========================================================================
// Incoming Call
// =========================================================================

function handleIncomingCall(session) {
  console.log('[VVP Phone] Incoming call');
  currentSession = session;

  // Send 180 Ringing
  try { session.progress(); } catch (_) { /* ignore */ }

  // Extract VVP headers
  const vvpData = VVPDisplay.extractFromSIPSession(session);
  console.log('[VVP Phone] VVP data:', vvpData);

  transition(CallState.RINGING, {
    vvpData,
    number: vvpData.caller_number || '',
  });

  // Session events
  session.on('accepted', () => {
    console.log('[VVP Phone] Call accepted');
    transition(CallState.IN_CALL, { vvpData });
    setupSessionAudio(session);
  });

  session.on('terminated', () => {
    console.log('[VVP Phone] Call terminated');
    currentSession = null;
    transition(CallState.IDLE);
  });

  session.on('failed', (_response, cause) => {
    console.log('[VVP Phone] Call failed:', cause);
    currentSession = null;
    transition(CallState.IDLE);
  });

  session.on('rejected', () => {
    console.log('[VVP Phone] Call rejected');
    currentSession = null;
    transition(CallState.IDLE);
  });
}


// =========================================================================
// Outbound Call
// =========================================================================

function makeCall(target) {
  if (!ua || !target) return;

  const domain = new URL(DEFAULT_SERVER).hostname;

  try {
    currentSession = ua.invite(`sip:${target}@${domain}`, {
      sessionDescriptionHandlerOptions: {
        constraints: { audio: true, video: false },
      },
    });

    transition(CallState.CALLING, { number: target });

    currentSession.on('accepted', () => {
      console.log('[VVP Phone] Outbound call accepted');
      transition(CallState.IN_CALL, { number: target });
      setupSessionAudio(currentSession);
    });

    currentSession.on('terminated', () => {
      console.log('[VVP Phone] Outbound call terminated');
      currentSession = null;
      transition(CallState.IDLE);
    });

    currentSession.on('failed', (_response, cause) => {
      console.log('[VVP Phone] Outbound call failed:', cause);
      currentSession = null;
      transition(CallState.IDLE);
    });
  } catch (e) {
    console.error('[VVP Phone] Dial error:', e);
    currentSession = null;
    transition(CallState.IDLE);
  }
}


// =========================================================================
// Call Actions
// =========================================================================

function acceptCall() {
  if (!currentSession) return;
  console.log('[VVP Phone] Accepting call');

  navigator.mediaDevices.getUserMedia({ audio: true, video: false })
    .then(() => {
      currentSession.accept({
        sessionDescriptionHandlerOptions: {
          constraints: { audio: true, video: false },
        },
      });
    })
    .catch(e => {
      console.error('[VVP Phone] Mic access error:', e);
    });
}

function declineCall() {
  if (!currentSession) return;
  console.log('[VVP Phone] Declining call');
  try { currentSession.reject(); } catch (_) { /* ignore */ }
  currentSession = null;
  transition(CallState.IDLE);
}

function hangUp() {
  if (!currentSession) return;
  console.log('[VVP Phone] Hanging up');
  try { currentSession.terminate(); } catch (_) { /* ignore */ }
  currentSession = null;
  transition(CallState.IDLE);
}


// =========================================================================
// Audio Setup (SIP.js 0.15.x)
// =========================================================================

function setupSessionAudio(session, attempt = 0) {
  const sdh = session.sessionDescriptionHandler;
  if (!sdh) {
    if (attempt < 20) {
      setTimeout(() => setupSessionAudio(session, attempt + 1), 200);
    }
    return;
  }

  const pc = sdh.peerConnection;
  if (!pc) return;

  const remoteAudio = document.getElementById('remote-audio');

  // Attach existing tracks
  pc.getReceivers().forEach(receiver => {
    if (receiver.track?.kind === 'audio') {
      remoteAudio.srcObject = new MediaStream([receiver.track]);
      remoteAudio.play().catch(() => {});
    }
  });

  // Listen for new tracks
  pc.ontrack = (event) => {
    if (event.track.kind === 'audio') {
      remoteAudio.srcObject = event.streams[0] || new MediaStream([event.track]);
      remoteAudio.play().catch(() => {});
    }
  };
}


// =========================================================================
// Initialization
// =========================================================================

document.addEventListener('DOMContentLoaded', () => {

  // Initialize dial pad
  UI.initDialPad();

  // Connect button
  document.getElementById('btn-connect').addEventListener('click', () => {
    const ext = document.getElementById('ext-select').value;
    const password = document.getElementById('password').value;

    if (!password) {
      UI.showLoginError('Please enter a password');
      return;
    }

    const remember = document.getElementById('remember').checked;
    if (remember) {
      saveCredentials(ext, password);
    }

    connect(ext, password);
  });

  // Disconnect button
  document.getElementById('btn-disconnect').addEventListener('click', disconnect);

  // Call button
  document.getElementById('btn-call').addEventListener('click', () => {
    const target = UI.getDialValue();
    if (target) makeCall(target);
  });

  // Accept / Decline / Hang Up
  document.getElementById('btn-accept').addEventListener('click', acceptCall);
  document.getElementById('btn-decline').addEventListener('click', () => {
    if (state === CallState.RINGING) declineCall();
    else hangUp();
  });

  // Auto-connect from saved credentials
  const saved = getSavedCredentials();
  if (saved) {
    document.getElementById('ext-select').value = saved.extension;
    document.getElementById('password').value = saved.password;
    document.getElementById('remember').checked = true;
    connect(saved.extension, saved.password);
  }
});
