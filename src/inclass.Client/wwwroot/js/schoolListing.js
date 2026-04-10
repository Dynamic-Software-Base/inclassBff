// wwwroot/js/schoolListing.js

/**
 * Initializes a Leaflet map inside a given container element.
 * Called from SchoolMapWidget.razor via JS interop.
 */
window.initLeafletMap = function (containerId, lat, lng, schoolName, city) {
    // If Leaflet CSS isn't injected yet, add it
    if (!document.getElementById('leaflet-css')) {
        const link = document.createElement('link');
        link.id = 'leaflet-css';
        link.rel = 'stylesheet';
        link.href = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css';
        document.head.appendChild(link);
    }

    const loadLeaflet = () => new Promise((resolve) => {
        if (window.L) return resolve();
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js';
        script.onload = resolve;
        document.head.appendChild(script);
    });

    loadLeaflet().then(() => {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Destroy any existing map instance on this element
        if (container._leaflet_id) {
            window.L.DomUtil.get(containerId)._leaflet_id = null;
        }

        // Remove old map if tracked
        if (window._leafletMaps && window._leafletMaps[containerId]) {
            window._leafletMaps[containerId].remove();
        }

        const map = window.L.map(containerId, {
            zoomControl: true,
            scrollWheelZoom: false,
        }).setView([lat, lng], 15);

        window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        }).addTo(map);

        const marker = window.L.marker([lat, lng]).addTo(map);
        marker.bindPopup(`<strong>${schoolName}</strong><br/>${city}`).openPopup();

        // Track for cleanup
        if (!window._leafletMaps) window._leafletMaps = {};
        window._leafletMaps[containerId] = map;
    });
};

/**
 * Scrolls a given element to the top.
 */
window.scrollToTop = function (elementId) {
    const el = document.getElementById(elementId);
    if (el) el.scrollTop = 0;
};
