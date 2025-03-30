/**
 * Sentinel Trading Platform - Service Worker
 * This service worker provides offline functionality and caching for the PWA
 */

const CACHE_NAME = 'sentinel-cache-v1';

// Resources to pre-cache at installation time
const PRECACHE_URLS = [
  '/',
  '/static/css/custom.css',
  '/static/js/app.js',
  '/static/js/app-installer.js',
  '/static/img/sentinel-logo.svg',
  '/static/img/icon-192.png',
  '/static/img/icon-512.png',
  '/templates/offline.html'
];

// Install event - cache initial resources
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_URLS))
      .then(self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  const currentCaches = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return cacheNames.filter(cacheName => !currentCaches.includes(cacheName));
    }).then(cachesToDelete => {
      return Promise.all(cachesToDelete.map(cacheToDelete => {
        return caches.delete(cacheToDelete);
      }));
    }).then(() => self.clients.claim())
  );
});

// Fetch event - cached resources and offline handling
self.addEventListener('fetch', event => {
  // Skip cross-origin requests like API calls
  if (event.request.url.startsWith(self.location.origin)) {
    event.respondWith(
      caches.match(event.request).then(cachedResponse => {
        if (cachedResponse) {
          return cachedResponse;
        }

        return fetch(event.request).then(response => {
          // If request fails, e.g. when offline
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }

          // Clone the response - one to cache, one to return
          const responseToCache = response.clone();

          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });

          return response;
        }).catch(error => {
          // For HTML pages, return the offline page
          if (event.request.mode === 'navigate') {
            return caches.match('/templates/offline.html');
          }
          
          // Return cached assets or null
          return caches.match(event.request);
        });
      })
    );
  }
});

// Push event - receive push notifications
self.addEventListener('push', event => {
  const title = 'Sentinel Trading Platform';
  const options = {
    body: event.data ? event.data.text() : 'New update from Sentinel',
    icon: '/static/img/icon-192.png',
    badge: '/static/img/sentinel-logo.svg'
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// Notification click event
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow('/')
  );
});