document.addEventListener('DOMContentLoaded', () => {
    const domainInput = document.getElementById('domainInput');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.querySelector('.btn-text');
    const loader = document.querySelector('.loader');
    const resultsGrid = document.getElementById('results');

    const terminal = document.getElementById('scanningTerminal');
    const terminalOutput = document.getElementById('terminalOutput');

    // Enter key handler
    domainInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            performScan();
        }
    });

    scanBtn.addEventListener('click', performScan);

    function addLogLine(text, type = '') {
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = text;
        terminalOutput.appendChild(line);
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }

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
        
        // Hide grid and show Terminal
        resultsGrid.classList.add('hidden');
        document.querySelectorAll('.card-content').forEach(el => el.innerHTML = '');
        terminalOutput.innerHTML = '';
        terminal.classList.remove('hidden');

        // Fake loading logs for dramatic effect
        const logs = [
            { text: `Initializing deep scan on target: ${url}...`, type: '', delay: 200 },
            { text: 'Bypassing edge cache layers...', type: '', delay: 600 },
            { text: 'Resolving DNS topology [A, AAAA, MX, NS, TXT]...', type: 'success', delay: 1100 },
            { text: 'Attempting WHOIS registry extraction...', type: '', delay: 1500 },
            { text: 'Probing network perimeter for open sockets...', type: 'warning', delay: 2200 },
            { text: 'Analyzing SSL/TLS cryptographic signatures...', type: 'success', delay: 2800 },
            { text: 'Triangulating server geolocation coordinates...', type: '', delay: 3400 },
            { text: 'Extracting hidden robots.txt directives...', type: 'warning', delay: 3900 },
            { text: 'Compiling reconnaissance packet...', type: 'success', delay: 4500 }
        ];

        let logOuts = [];
        logs.forEach(log => {
            let timeout = setTimeout(() => {
                addLogLine(log.text, log.type);
            }, log.delay);
            logOuts.push(timeout);
        });

        const startTime = Date.now();

        try {
            const response = await fetch(`/api/scan?url=${encodeURIComponent(url)}`);
            const data = await response.json();

            // Ensure our dramatic animation plays for at least a few seconds 
            // even if the API comes back instantly
            const timeElapsed = Date.now() - startTime;
            const minimumDelay = 5000;
            if (timeElapsed < minimumDelay) {
                await new Promise(resolve => setTimeout(resolve, minimumDelay - timeElapsed));
            }

            if (response.ok) {
                terminal.classList.add('hidden');
                
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
                addLogLine(`CRITICAL ERROR: ${data.detail || 'Failed to analyze domain'}`, 'error');
            }
        } catch (error) {
            addLogLine('CRITICAL FAILURE: Network connection to server lost.', 'error');
            console.error(error);
        } finally {
            // Restore UI Search State
            logOuts.forEach(clearTimeout);
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

        // Geolocation
        const geoEl = document.getElementById('geoContent');
        if (data.geolocation && !data.geolocation.error) {
            const { ip, country, region, city, isp, org } = data.geolocation;
            geoEl.innerHTML = `
                <div class="data-row"><span class="data-key">IP Address:</span><span class="data-value">${ip || 'N/A'}</span></div>
                <div class="data-row"><span class="data-key">Country:</span><span class="data-value">${country || 'N/A'}</span></div>
                <div class="data-row"><span class="data-key">Region/City:</span><span class="data-value">${region || 'N/A'}, ${city || 'N/A'}</span></div>
                <div class="data-row"><span class="data-key">ISP:</span><span class="data-value">${isp || 'N/A'}</span></div>
                <div class="data-row"><span class="data-key">Organization:</span><span class="data-value">${org || 'N/A'}</span></div>
            `;
        } else {
            geoEl.innerHTML = `<span class="error-text">Geolocation data unavailable (${data.geolocation?.error || 'Unknown error'}).</span>`;
        }

        // Robots.txt
        const robotsEl = document.getElementById('robotsContent');
        if (data.robots_txt && data.robots_txt.found) {
            const lines = data.robots_txt.content;
            const total = data.robots_txt.total_lines;
            robotsEl.innerHTML = `
                <div class="data-row" style="flex-direction: column; align-items: flex-start;">
                    <span class="data-key" style="margin-bottom: 0.8rem;">Robots.txt found (${total} lines):</span>
                    <div style="background: rgba(0,0,0,0.2); width: 100%; box-sizing: border-box; padding: 0.5rem; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.85em; max-height: 150px; overflow-y: auto;">
                        ${lines.join('<br>')}
                        ${total > lines.length ? '<br><i>...truncated</i>' : ''}
                    </div>
                </div>
            `;
        } else {
            robotsEl.innerHTML = `<span class="empty-text">No robots.txt found or accessible.</span>`;
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
