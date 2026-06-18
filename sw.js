const CACHE='sob-v1';
self.addEventListener('install',e=>e.waitUntil(
  caches.open(CACHE).then(c=>c.addAll(['./','./index.html','./stckovrbrd.png','./icon-192.png','./icon-512.png']))
));
self.addEventListener('fetch',e=>e.respondWith(
  fetch(e.request).catch(()=>caches.match(e.request))
));
