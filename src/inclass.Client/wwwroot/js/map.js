window.mapInterop = {
    _maps: {},

    init: function (containerId, lat, lng, zoom = 13) {
        // Destroy existing instance if re-initializing
        if (this._maps[containerId]) {
            this._maps[containerId].remove();
            delete this._maps[containerId];
        }

        const map = L.map(containerId, { zoomControl: true, scrollWheelZoom: false })
            .setView([lat, lng], zoom);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);

        L.marker([lat, lng]).addTo(map);

        this._maps[containerId] = map;
    },

    update: function (containerId, lat, lng) {
        const map = this._maps[containerId];
        if (!map) return;
        map.setView([lat, lng], 13);
        // Remove old markers and add new one
        map.eachLayer(layer => { if (layer instanceof L.Marker) map.removeLayer(layer); });
        L.marker([lat, lng]).addTo(map);
    },

    destroy: function (containerId) {
        if (this._maps[containerId]) {
            this._maps[containerId].remove();
            delete this._maps[containerId];
        }
    }
};