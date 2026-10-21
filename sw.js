/* Garde des enfants : application installable et lecture hors connexion. */
const CACHE = 'garde-1.1.0';
const STATIC = [
  'assets/app.css', 'assets/app.js', 'assets/calendar.js',
  'assets/icons/icon-192.png', 'offline.html', 'manifest.webmanifest',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(STATIC)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

function offlineCopy(res) {
  const h = new Headers(res.headers);
  h.set('X-Garde-Offline', '1');
  return res.blob().then((b) => new Response(b, { status: res.status, statusText: res.statusText, headers: h }));
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Données : toujours le réseau d’abord ; sans réseau, la dernière version lue (planning et réglages seulement).
  if (url.pathname.endsWith('/api.php')) {
    const a = url.searchParams.get('a');
    if (a !== 'boot' && a !== 'weeks') return;
    e.respondWith(
      fetch(req).then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
        return res;
      }).catch(() => caches.match(req).then((hit) => (hit ? offlineCopy(hit) : Response.error())))
    );
    return;
  }

  // Page : réseau d’abord ; on ne garde que la page de l’application (jamais la page de connexion).
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).then((res) => {
        if (res.ok && res.headers.get('X-Garde-App') === '1') {
          const copy = res.clone(); caches.open(CACHE).then((c) => c.put('app-shell', copy));
        }
        return res;
      }).catch(() => caches.match('app-shell').then((hit) => hit || caches.match('offline.html')))
    );
    return;
  }

  // Fichiers du site : réseau d’abord, copie locale en secours.
  e.respondWith(
    fetch(req).then((res) => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req, { ignoreSearch: true }).then((hit) => hit || Response.error()))
  );
});
