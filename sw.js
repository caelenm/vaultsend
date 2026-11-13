// VaultSend service worker: lets the installed app open with no connection.
//
// It only ever fetches VaultSend's own files, from the origin it was served from,
// and keeps the last copy of each. Network first, so a new version is picked up
// as soon as there is a connection; the kept copy is used when there is none.
// It reads nothing the page holds: no keys, no messages, no files pass through
// here, because the page itself makes no requests (its CSP has connect-src 'none').
//
// The page still refuses to run any script whose SHA-256 is not pinned in its
// own CSP, whichever copy this worker hands it.
const CACHE = "vaultsend-v1";
const FILES = ["./", "manifest.webmanifest", "icons/icon-192.png", "icons/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET" || new URL(req.url).origin !== self.location.origin) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const fresh = await fetch(req, { cache: "no-cache" });
      if (fresh.ok) await cache.put(req, fresh.clone());
      return fresh;
    } catch (err) {
      const kept = await cache.match(req, { ignoreSearch: true })
        || (req.mode === "navigate" ? await cache.match("./") : undefined);
      if (kept) return kept;
      throw err;
    }
  })());
});
