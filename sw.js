/* ================================================================
 * BradiCoin Wallet — Service Worker (v2, resilient)
 * - Cache versionado
 * - network-first para a API e navegação
 * - cache-first para assets estáticos
 * - skipWaiting + clients.claim (ativa imediatamente)
 * - Nunca bloqueia o install se um asset faltar
 * ================================================================ */

const CACHE_VERSION = 'bradicoin-wallet-v2';
const STATIC_CACHE  = `${CACHE_VERSION}-static`;
const RUNTIME_CACHE = `${CACHE_VERSION}-runtime`;

// Assets locais. Use caminhos RELATIVOS — funcionam no GitHub Pages E no APK.
const PRECACHE_URLS = [
  './',
  './index.html',
  './generetor-wallets.html',
  './logo-bradicoin.png',
  './logo-small.png',
  './manifest.json'
];

// Hosts que NUNCA devem ser cacheados (API, WebSocket, CDNs de terceiros)
const NEVER_CACHE_HOSTS = [
  'bradicoin-api.onrender.com'
];

// ================================================================
// INSTALL — pré-cache tolerante a falhas
// ================================================================
self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(STATIC_CACHE);
    // addAll() aborta tudo se 1 falhar. Vamos 1 por 1.
    await Promise.all(PRECACHE_URLS.map(async url => {
      try {
        const res = await fetch(url, { cache: 'no-cache' });
        if (res && res.ok) await cache.put(url, res);
      } catch (err) {
        console.warn('[SW] Skipping precache for', url, err.message);
      }
    }));
    // Ativa o novo SW imediatamente
    self.skipWaiting();
  })());
});

// ================================================================
// ACTIVATE — limpa caches antigos e assume controle das abas
// ================================================================
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys
        .filter(k => k !== STATIC_CACHE && k !== RUNTIME_CACHE)
        .map(k => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

// ================================================================
// FETCH — estratégia por tipo de request
// ================================================================
self.addEventListener('fetch', event => {
  const req = event.request;

  // Só intercepta GET. POST/PUT/DELETE vão direto para a rede.
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Nunca cacheia API, WebSocket, ou hosts externos críticos
  if (NEVER_CACHE_HOSTS.includes(url.hostname)) return;
  if (url.protocol === 'ws:' || url.protocol === 'wss:') return;

  // Requests de navegação (abrir/recarregar a página)
  if (req.mode === 'navigate') {
    event.respondWith(networkFirst(req));
    return;
  }

  // Assets do mesmo host (html, css, js, imagens, fonts)
  if (url.origin === self.location.origin) {
    event.respondWith(cacheFirst(req));
    return;
  }

  // CDNs externas (fonts, crypto-js, elliptic, etc.)
  // Usa stale-while-revalidate para atualizar em background.
  event.respondWith(staleWhileRevalidate(req));
});

// ================================================================
// ESTRATÉGIAS
// ================================================================

// Tenta rede primeiro; se falhar, usa cache; se nem cache, devolve index.html
async function networkFirst(req) {
  try {
    const res = await fetch(req);
    // Cacheia uma cópia da navegação bem-sucedida
    const cache = await caches.open(RUNTIME_CACHE);
    cache.put(req, res.clone()).catch(() => {});
    return res;
  } catch (err) {
    const cached = await caches.match(req);
    if (cached) return cached;
    // Fallback final: shell do app
    const shell = await caches.match('./index.html');
    if (shell) return shell;
    return new Response(
      '<h1>Offline</h1><p>BradiCoin Wallet is offline. Reconnect and try again.</p>',
      { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }
}

// Cache primeiro (rápido); se não tiver, busca na rede
async function cacheFirst(req) {
  const cached = await caches.match(req);
  if (cached) return cached;
  try {
    const res = await fetch(req);
    if (res && res.ok) {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(req, res.clone()).catch(() => {});
    }
    return res;
  } catch (err) {
    return new Response('', { status: 504, statusText: 'Offline' });
  }
}

// Devolve do cache imediatamente e atualiza em background
async function staleWhileRevalidate(req) {
  const cached = await caches.match(req);
  const networkPromise = fetch(req)
    .then(async res => {
      if (res && res.ok) {
        const cache = await caches.open(RUNTIME_CACHE);
        cache.put(req, res.clone()).catch(() => {});
      }
      return res;
    })
    .catch(() => null);

  return cached || (await networkPromise) || new Response('', { status: 504 });
}

// ================================================================
// MESSAGE — permite forçar atualização via postMessage
// ================================================================
self.addEventListener('message', event => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});
