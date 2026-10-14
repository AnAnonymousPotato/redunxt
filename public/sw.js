const CACHE_NAME = 'redunxt-pwa-v2';

self.addEventListener('install', (e) => {
  self.skipWaiting();
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
    icon: '/favicon.svg',
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
    icon: data.icon || '/favicon.svg',
    badge: '/favicon.svg',
    data: {
      url: data.url || '/'
    },
    tag: data.tag || 'redunxt-notification',
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
