document.addEventListener('DOMContentLoaded', () => {
    const domainInput = document.getElementById('domainInput');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.querySelector('.btn-text');
    const loader = document.querySelector('.loader');
    const resultsGrid = document.getElementById('results');

    // Enter key handler
    domainInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            performScan();
        }
    });

    scanBtn.addEventListener('click', performScan);

    async function performScan() {
        const url = domainInput.value.trim();
        if (!url) {
            domainInput.focus();
            return;
        }

        // Setup Loading State
        btnText.classList.add('hidden');
        loader.classList.remove('hidden');
        scanBtn.disabled = true;
        
        // Hide and clear results
        resultsGrid.classList.add('hidden');
        document.querySelectorAll('.card-content').forEach(el => el.innerHTML = '');

        try {
            const response = await fetch(`/api/scan?url=${encodeURIComponent(url)}`);
            const data = await response.json();

            if (response.ok) {
                renderResults(data);
                // Retrigger animations
                const cards = document.querySelectorAll('.card');
                cards.forEach(card => {
                    card.style.animation = 'none';
                    card.offsetHeight; /* trigger reflow */
                    card.style.animation = null; 
                });
                
                resultsGrid.classList.remove('hidden');
            } else {
                alert(`Error: ${data.detail || 'Failed to analyze domain'}`);
            }
        } catch (error) {
            alert('A network error occurred connecting to the backend server.');
            console.error(error);
        } finally {
            // Restore UI Search State
            btnText.classList.remove('hidden');
            loader.classList.add('hidden');
            scanBtn.disabled = false;
        }
    }

    function renderResults(data) {
        // WHOIS
        const whoisEl = document.getElementById('whoisContent');
        if (data.whois && !data.whois.error && Object.keys(data.whois).length > 0) {
            const keys = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'emails', 'name_servers'];
            let html = '';
            for (const key of keys) {
                if (data.whois[key]) {
                    html += `<div class="data-row">
                        <span class="data-key">${formatKey(key)}:</span>
                        <span class="data-value">${formatValue(data.whois[key])}</span>
                    </div>`;
                }
            }
            whoisEl.innerHTML = html || '<span class="empty-text">No significant WHOIS data found.</span>';
        } else {
            whoisEl.innerHTML = `<span class="error-text">Retrieval Failed: ${data.whois?.error || 'Private/No Data'}</span>`;
        }

        // DNS
        const dnsEl = document.getElementById('dnsContent');
        if (data.dns && Object.keys(data.dns).length > 0) {
            let html = '';
            for (const [recordType, records] of Object.entries(data.dns)) {
                if (records && records.length > 0) {
                    html += `<div class="data-row">
                        <span class="data-key">${recordType} Records:</span>
                        <span class="data-value">
                            ${records.map(r => `<span class="tag">${r}</span>`).join('')}
                        </span>
                    </div>`;
                }
            }
            dnsEl.innerHTML = html || '<span class="empty-text">No DNS records found.</span>';
        } else {
            dnsEl.innerHTML = '<span class="empty-text">No accessible DNS infrastructure details found.</span>';
        }

        // Open Ports
        const portsEl = document.getElementById('portsContent');
        if (data.open_ports && data.open_ports.length > 0) {
            portsEl.innerHTML = `<div class="data-row" style="flex-direction: column;">
                <span class="data-key" style="margin-bottom: 0.8rem;">Discovered Open Ports:</span>
                <span class="data-value">
                    ${data.open_ports.map(p => {
                        const portName = getCommonPortName(p);
                        return `<span class="tag port" title="${portName}">Port ${p} (${portName})</span>`;
                    }).join('')}
                </span>
            </div>`;
        } else {
            portsEl.innerHTML = '<span class="empty-text">No common accessible ports detected (Shielded/Firewalled).</span>';
        }

        // SSL
        const sslEl = document.getElementById('sslContent');
        if (data.ssl && !data.ssl.error) {
            const { issuer, subject, version, notBefore, notAfter } = data.ssl;
            sslEl.innerHTML = `
                <div class="data-row"><span class="data-key">Issuer:</span><span class="data-value">${issuer?.organizationName || issuer?.commonName || 'Unknown Auth'}</span></div>
                <div class="data-row"><span class="data-key">Subject:</span><span class="data-value">${subject?.commonName || subject?.organizationName || 'Unknown Subject'}</span></div>
                <div class="data-row"><span class="data-key">Valid From:</span><span class="data-value">${notBefore || 'N/A'}</span></div>
                <div class="data-row"><span class="data-key">Valid To:</span><span class="data-value">${notAfter || 'N/A'}</span></div>
                <div class="data-row"><span class="data-key">Version:</span><span class="data-value">v${version || '?'}</span></div>
            `;
        } else {
            sslEl.innerHTML = `<span class="error-text">No valid SSL configuration extracted (${data.ssl?.error || 'No HTTPS context'}).</span>`;
        }

        // Headers
        const headersEl = document.getElementById('headersContent');
        if (data.headers && !data.headers.error) {
            let html = '';
            // Sort keys alphabetically
            const sortedKeys = Object.keys(data.headers).sort();
            for (const key of sortedKeys) {
                // Highlight security headers
                const isSecurity = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'server'].includes(key.toLowerCase());
                const keyStyle = isSecurity ? 'color: #38bdf8;' : '';
                
                html += `<div class="data-row">
                    <span class="data-key" style="${keyStyle}">${key}:</span>
                    <span class="data-value">${data.headers[key]}</span>
                </div>`;
            }
            headersEl.innerHTML = html;
        } else {
            headersEl.innerHTML = `<span class="error-text">Server response analysis failed or host unreachable.</span>`;
        }
    }

    function formatKey(key) {
        return key.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    }

    function formatValue(value) {
        if (Array.isArray(value)) {
            // If it's a long array, slice it and add tags
            if (value.length > 8) {
                return value.slice(0, 8).map(v => `<span class="tag" style="background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.1); color: #ccc;">${v}</span>`).join('') + ` & ${value.length - 8} more...`;
            }
            return value.map(v => `<span class="tag" style="background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.1); color: #ccc;">${v}</span>`).join('');
        }
        return value;
    }
    
    function getCommonPortName(port) {
        const map = {
            21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 
            80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 
            8443: 'HTTPS-Alt', 3306: 'MySQL'
        };
        return map[port] || 'Unknown';
    }
});
