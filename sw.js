// Fixer OS Essencial (hub) — Service Worker (gerado por _SISTEMA/scripts/gerar_sw.py em 2026-10-23)
// Rede primeiro (quem já usa a app recebe sempre a versão publicada) e cache versionada.
// Caminhos RELATIVOS: no GitHub Pages a app vive em /<repo>/ — "/index.html" apontava para a raiz do domínio
// e a instalação falhava. Ao publicar um front novo, voltar a gerar (muda CACHE).
const CACHE = 'fixeros-essencial-2026-10-23';
const ASSETS = ["./", "./index.html", "./manifest.json", "./fixeros-auth.js", "./icon-192.png", "./icon-512.png"];

self.addEventListener('install', e => {
  // Cada ficheiro à parte: um ícone em falta não pode impedir a instalação
  e.waitUntil(caches.open(CACHE).then(c => Promise.all(ASSETS.map(a => c.add(a).catch(() => null)))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  if (e.request.url.includes('script.google.com')) return;   // a API nunca passa pela cache
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;             // CDN e fontes: o browser trata
  const ehHtml = e.request.mode === 'navigate' || url.pathname.endsWith('/') || url.pathname.endsWith('.html');
  const guardar = resp => { if (resp.ok) { const copia = resp.clone(); caches.open(CACHE).then(c => c.put(e.request, copia)); } return resp; };

  if (ehHtml) {
    e.respondWith(fetch(e.request).then(guardar).catch(() => caches.match(e.request).then(c => c || caches.match('./index.html'))));
    return;
  }
  // Restantes ficheiros (js, ícones): rede primeiro também — são poucos e mudam junto com o HTML
  e.respondWith(fetch(e.request).then(guardar).catch(() => caches.match(e.request)));
});
