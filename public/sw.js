// Vigía service worker: makes the dashboard installable and lets the shell open without a connection.
// Data (/api, /report) is never cached: an alert screen must not show stale alerts as if they were current.
const CACHE = 'vigia-shell-0.14.0';
const SHELL = ['/', '/app.css', '/app.js', '/model.js', '/icons.js', '/editor.js', '/validate.js', '/theme.js', '/icon.svg', '/manifest.webmanifest'];

self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/') || url.pathname === '/report') return;
  // network first (the server is the source of truth, and updates must show up), cached shell when offline
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request).then(m => m || caches.match('/'))));
});
