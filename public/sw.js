const CACHE_NAME = 'redunxt-pwa-v3';

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(['/icon-192.png', '/badge-96.png', '/favicon.svg']);
    }).catch(() => null)
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (e) => {
  // Never intercept API or Cloudflare backend requests
  if (e.request.url.includes('/api/') || e.request.url.includes('workers.dev')) {
    return;
  }
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});

// Push notification received in background (app closed or in background)
self.addEventListener('push', (event) => {
  let data = {
    title: 'Redunxt Notification',
    body: 'New update from school',
    icon: '/icon-192.png',
    badge: '/badge-96.png',
    url: '/'
  };

  if (event.data) {
    try {
      data = event.data.json();
    } catch {
      data.body = event.data.text();
    }
  }

  const options = {
    body: data.body || 'You have a new school update.',
    icon: data.icon || '/icon-192.png',
    badge: '/badge-96.png',
    data: {
      url: data.url || '/'
    },
    tag: data.tag || ('redunxt-' + Date.now()),
    renotify: true,
    vibrate: [200, 100, 200]
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'Redunxt', options)
  );
});

// User tapped notification banner
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || '/';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          if (targetUrl && targetUrl !== '/') {
            client.navigate(targetUrl);
          }
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});
