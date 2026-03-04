/**
 * VVP Phone PWA — Service Worker
 *
 * Caches the app shell for offline startup. SIP/WebSocket traffic
 * is not cached (it's real-time over WebSocket, not HTTP).
 *
 * Credential safety: This service worker is scoped to /phone/ on pbx.rcnx.io.
 * API calls (to vvp-issuer.rcnx.io) are cross-origin requests — service workers
 * do NOT intercept cross-origin fetch requests. No credentials or API keys can
 * be captured or cached by this worker. The APP_SHELL list is the complete set
 * of cacheable resources; everything else falls through to the network.
 */

const CACHE_NAME = 'vvp-phone-v1';

const APP_SHELL = [
  '/phone',
  'css/phone.css',
  'js/app.js',
  'js/vvp-display.js',
  'js/ui.js',
  'manifest.json',
  'img/icon-192.png',
  'img/icon-512.png',
  'img/vvp-logo-placeholder.svg',
  'https://cdn.jsdelivr.net/npm/sip.js@0.15.11/dist/sip.min.js',
];

// Install: pre-cache app shell
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// Fetch: cache-first for app shell, network-first for everything else
self.addEventListener('fetch', (event) => {
  // Skip WebSocket and non-GET requests
  if (event.request.url.startsWith('ws') || event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then(cached => cached || fetch(event.request))
  );
});
