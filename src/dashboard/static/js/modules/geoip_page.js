/**
 * GeoIP Lookup Page Module
 * Handles IP geolocation lookups and statistics
 */

// Load GeoIP page data
async function loadGeoIPPage() {
    await Promise.all([
        loadGeoIPStats(),
        loadGeoIPTopCountries(),
        loadGeoIPRecent()
    ]);
}

// Load GeoIP statistics
async function loadGeoIPStats() {
    try {
        const response = await fetch('/api/geoip/stats');
        const data = await response.json();

        if (data.success && data.stats) {
            const stats = data.stats;
            document.getElementById('stat-total-geoips').textContent = stats.total_ips.toLocaleString();

            const threatIndicators = stats.threat_indicators || {};
            document.getElementById('stat-proxy-count').textContent =
                ((threatIndicators.proxy_count || 0) + (threatIndicators.vpn_count || 0)).toLocaleString();
            document.getElementById('stat-tor-count').textContent =
                (threatIndicators.tor_count || 0).toLocaleString();
            document.getElementById('stat-datacenter-count').textContent =
                (threatIndicators.datacenter_count || 0).toLocaleString();
        }
    } catch (error) {
        console.error('Error loading GeoIP stats:', error);
    }
}

// Load top countries
async function loadGeoIPTopCountries() {
    const container = document.getElementById('geoip-top-countries');

    try {
        const response = await fetch('/api/geoip/stats');
        const data = await response.json();

        if (!data.success || !data.stats.top_countries || data.stats.top_countries.length === 0) {
            container.innerHTML = '<div class="empty-state-small">No country data available</div>';
            return;
        }

        const countries = data.stats.top_countries;
        container.innerHTML = `
            <div class="table-wrapper">
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <th style="text-align: left; padding: 10px; font-weight: 600; font-size: 13px;">Country</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Code</th>
                        <th style="text-align: right; padding: 10px; font-weight: 600; font-size: 13px;">IP Count</th>
                    </tr>
                </thead>
                <tbody>
                    ${countries.map(country => `
                        <tr style="border-bottom: 1px solid var(--border-light);">
                            <td style="padding: 10px; font-size: 13px;">${escapeHtml(country.country_name || 'Unknown')}</td>
                            <td style="text-align: center; padding: 10px; font-size: 13px;">${escapeHtml(country.country_code || 'N/A')}</td>
                            <td style="text-align: right; padding: 10px; font-size: 13px; font-weight: 600;">${country.count.toLocaleString()}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            </div>
        `;
    } catch (error) {
        console.error('Error loading top countries:', error);
        container.innerHTML = '<div class="empty-state-small" style="color: #D13438;">Error loading countries</div>';
    }
}

// Load recent GeoIP lookups
async function loadGeoIPRecent() {
    const container = document.getElementById('geoip-recent-list');

    try {
        const response = await fetch('/api/geoip/recent?limit=20');
        const data = await response.json();

        if (!data.success || !data.data || data.data.length === 0) {
            container.innerHTML = '<div class="empty-state-small">No recent lookups</div>';
            return;
        }

        container.innerHTML = `
            <div class="table-wrapper">
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <th style="text-align: left; padding: 10px; font-weight: 600; font-size: 13px;">IP Address</th>
                        <th style="text-align: left; padding: 10px; font-weight: 600; font-size: 13px;">Country</th>
                        <th style="text-align: left; padding: 10px; font-weight: 600; font-size: 13px;">City</th>
                        <th style="text-align: left; padding: 10px; font-weight: 600; font-size: 13px;">ASN Org</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Flags</th>
                        <th style="text-align: right; padding: 10px; font-weight: 600; font-size: 13px;">Last Seen</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.data.map(ip => {
                        const flags = [];
                        if (ip.is_proxy) flags.push('🔴 Proxy');
                        if (ip.is_vpn) flags.push('🔵 VPN');
                        if (ip.is_tor) flags.push('🟣 Tor');

                        return `
                            <tr style="border-bottom: 1px solid var(--border-light);">
                                <td style="padding: 10px; font-size: 13px; font-family: monospace;">${escapeHtml(ip.ip_address_text)}</td>
                                <td style="padding: 10px; font-size: 13px;">${escapeHtml(ip.country_name || 'N/A')}</td>
                                <td style="padding: 10px; font-size: 13px;">${escapeHtml(ip.city || 'N/A')}</td>
                                <td style="padding: 10px; font-size: 13px;">${escapeHtml(ip.asn_org || 'N/A')}</td>
                                <td style="text-align: center; padding: 10px; font-size: 12px;">${flags.join(' ') || '-'}</td>
                                <td style="text-align: right; padding: 10px; font-size: 13px;">${ip.last_seen ? formatLocalDateTime(ip.last_seen) : 'N/A'}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        console.error('Error loading recent GeoIP data:', error);
        container.innerHTML = '<div class="empty-state-small" style="color: #D13438;">Error loading recent lookups</div>';
    }
}

// Lookup specific IP
async function lookupGeoIP() {
    const input = document.getElementById('geoip-search-input');
    const resultContainer = document.getElementById('geoip-lookup-result');
    const ipAddress = input.value.trim();

    if (!ipAddress) {
        resultContainer.innerHTML = '<div style="color: #D13438; font-size: 13px;">Please enter an IP address</div>';
        return;
    }

    resultContainer.innerHTML = '<div class="loading-message">Looking up IP address...</div>';

    try {
        const response = await fetch(`/api/geoip/lookup/${encodeURIComponent(ipAddress)}`);
        const data = await response.json();

        if (!data.success) {
            // IP not found - offer to enrich it
            resultContainer.innerHTML = `
                <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                    <div style="color: #D13438; font-size: 14px; font-weight: 600; margin-bottom: 8px;">IP Not Found in Database</div>
                    <div style="font-size: 13px; margin-bottom: 16px;">${data.message || data.error || 'This IP has not been enriched yet.'}</div>
                    <div style="font-size: 13px; margin-bottom: 12px;">Would you like to enrich this IP now? This will fetch geolocation data from external services.</div>
                    <button
                        onclick="enrichGeoIP('${escapeHtml(ipAddress)}')"
                        style="padding: 8px 16px; background: var(--azure-blue); color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 13px; font-weight: 600;"
                    >
                        Enrich IP Address
                    </button>
                </div>
            `;
            return;
        }

        const geo = data.data;
        const flags = [];
        if (geo.is_proxy) flags.push('🔴 Proxy');
        if (geo.is_vpn) flags.push('🔵 VPN');
        if (geo.is_tor) flags.push('🟣 Tor');
        if (geo.is_datacenter) flags.push('🟠 Datacenter');

        resultContainer.innerHTML = `
            <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                <div style="font-size: 16px; font-weight: 600; margin-bottom: 16px; color: var(--azure-blue);">
                    IP: ${escapeHtml(geo.ip_address_text)}
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; font-size: 13px;">
                    <div><strong>Country:</strong> ${escapeHtml(geo.country_name || 'Unknown')} (${escapeHtml(geo.country_code || 'N/A')})</div>
                    <div><strong>Region:</strong> ${escapeHtml(geo.region || 'N/A')}</div>
                    <div><strong>City:</strong> ${escapeHtml(geo.city || 'N/A')}</div>
                    <div><strong>Postal Code:</strong> ${escapeHtml(geo.postal_code || 'N/A')}</div>
                    <div><strong>Latitude:</strong> ${geo.latitude || 'N/A'}</div>
                    <div><strong>Longitude:</strong> ${geo.longitude || 'N/A'}</div>
                    <div><strong>ASN:</strong> ${geo.asn || 'N/A'}</div>
                    <div><strong>ASN Org:</strong> ${escapeHtml(geo.asn_org || 'N/A')}</div>
                    <div><strong>ISP:</strong> ${escapeHtml(geo.isp || 'N/A')}</div>
                    <div><strong>Organization:</strong> ${escapeHtml(geo.organization || 'N/A')}</div>
                    ${flags.length > 0 ? `<div style="grid-column: 1 / -1;"><strong>Indicators:</strong> ${flags.join(' ')}</div>` : ''}
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error looking up IP:', error);
        resultContainer.innerHTML = `
            <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                <div style="color: #D13438; font-size: 14px;">Connection Error</div>
                <div style="font-size: 13px; margin-top: 8px;">Failed to lookup IP address. Please try again.</div>
            </div>
        `;
    }
}

// Enrich IP with GeoIP data
async function enrichGeoIP(ipAddress) {
    const resultContainer = document.getElementById('geoip-lookup-result');

    resultContainer.innerHTML = '<div class="loading-message">Enriching IP address... This may take a few seconds.</div>';

    try {
        const response = await fetch(`/api/geoip/enrich/${encodeURIComponent(ipAddress)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            resultContainer.innerHTML = `
                <div style="padding: 20px; background: #E7F5E7; border: 1px solid #107C10; border-radius: 3px;">
                    <div style="color: #107C10; font-size: 14px; font-weight: 600; margin-bottom: 8px;">✅ Enrichment Successful!</div>
                    <div style="font-size: 13px; margin-bottom: 12px;">IP address has been enriched and added to the database.</div>
                    <button
                        onclick="lookupGeoIP()"
                        style="padding: 8px 16px; background: var(--azure-blue); color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 13px; font-weight: 600;"
                    >
                        View Details
                    </button>
                </div>
            `;

            // Refresh the page data
            loadGeoIPPage();
        } else {
            resultContainer.innerHTML = `
                <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                    <div style="color: #D13438; font-size: 14px; font-weight: 600; margin-bottom: 8px;">Enrichment Failed</div>
                    <div style="font-size: 13px;">${data.error || 'Unknown error occurred'}</div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error enriching IP:', error);
        resultContainer.innerHTML = `
            <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                <div style="color: #D13438; font-size: 14px;">Connection Error</div>
                <div style="font-size: 13px; margin-top: 8px;">Failed to enrich IP address. Please try again.</div>
            </div>
        `;
    }
}

// Enable Enter key for lookup
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('geoip-search-input');
    if (input) {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                lookupGeoIP();
            }
        });
    }
});
