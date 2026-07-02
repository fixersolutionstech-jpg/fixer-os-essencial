const CACHE = 'fixeros-essencial-v1';
const ASSETS = ['/', '/index.html', '/manifest.json', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  if (e.request.url.includes('script.google.com')) return;
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request)
      .then(resp => { if (resp.ok && e.request.method === 'GET') caches.open(CACHE).then(c => c.put(e.request, resp.clone())); return resp; })
    ).catch(() => caches.match('/index.html'))
  );
});
