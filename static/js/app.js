// Veriscope Web Interface JavaScript

let currentResults = null;
let selectedIOCs = {
    urls: [],
    ips: [],
    domains: [],
    registry_keys: [],
    mutexes: [],
    file_paths: [],
    crypto_addresses: []
};

let selectedDeobfuscated = [];

// Handle form submission
document.getElementById('upload-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const loadingDiv = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');

    // Show loading, hide results
    loadingDiv.style.display = 'block';
    resultsDiv.style.display = 'none';

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Analysis failed');
        }

        const data = await response.json();
        currentResults = data;

        // Reset selections
        selectedIOCs = {
            urls: [],
            ips: [],
            domains: [],
            registry_keys: [],
            mutexes: [],
            file_paths: [],
            crypto_addresses: []
        };
        selectedDeobfuscated = [];

        // Update summary cards
        document.getElementById('stat-strings').textContent = data.summary.strings;
        document.getElementById('stat-decoded').textContent = data.summary.decoded || 0;
        document.getElementById('stat-iocs').textContent = data.summary.iocs;
        document.getElementById('stat-techniques').textContent = data.summary.techniques;

        // Populate Deobfuscation tab
        if (data.deobfuscation_stats) {
            displayDeobfuscation(data.deobfuscation_stats, data.deobfuscation_results);
        }

        // Populate IOCs tab
        displayIOCs(data.iocs);

        // Populate ATT&CK tab
        displayAttackMapping(data.attack_mapping);

        // Populate YARA tab
        displayYaraRules(data.yara_rule, data.yara_ioc_rules);

        // Populate Sigma tab
        displaySigmaRules(data.sigma_rule, data.sigma_ioc_rules);

        // Populate Report tab
        displayReport(data.markdown_report);

        // Show results
        loadingDiv.style.display = 'none';
        resultsDiv.style.display = 'block';

        // Scroll to results
        resultsDiv.scrollIntoView({ behavior: 'smooth' });

    } catch (error) {
        alert('Error: ' + error.message);
        loadingDiv.style.display = 'none';
    }
});

// Display Deobfuscation Results with checkboxes
function displayDeobfuscation(stats, results) {
    const container = document.getElementById('deobfuscation-content');
    let html = '';

    // Stats summary
    html += '<div class="deobf-stats">';
    html += '<h4>◈ Summary</h4>';
    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">';
    html += '<div><strong>Decoded Strings:</strong> ' + (stats.successfully_decoded || 0) + '</div>';
    html += '<div><strong>Max Depth:</strong> ' + (stats.max_depth || 0) + ' layers</div>';

    // Count suspicious patterns from results directly
    const suspiciousCount = results ? results.filter(r => r.suspicious_patterns && r.suspicious_patterns.length > 0).length : 0;
    html += '<div><strong>Suspicious:</strong> ' + suspiciousCount + '</div>';
    html += '</div>';

    if (stats.methods_used && stats.methods_used.length > 0) {
        html += '<div style="margin-top: 15px;"><strong>Methods:</strong> ' + stats.methods_used.join(', ') + '</div>';
    }
    html += '</div>';

    // Decoded samples with checkboxes
    if (results && results.length > 0) {
        html += '<div style="margin: 20px 0; display: flex; justify-content: space-between; align-items: center;">';
        html += '<h4>◈ Decoded Samples (Select for Rule Generation)</h4>';
        html += '<button class="btn-secondary" onclick="generateCustomRules()">Generate Rules from Selection</button>';
        html += '</div>';

        results.slice(0, 10).forEach((result, i) => {
            html += '<div class="deobf-sample">';

            // Checkbox and header
            html += '<div class="deobf-sample-header">';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="deobf-checkbox" data-index="' + i + '" onchange="toggleDeobfSelection(this, ' + i + ')">';
            html += '<strong>Sample ' + (i + 1) + '</strong>';
            html += '</label>';
            html += '<span>Layers: ' + result.layers + '</span>';
            html += '</div>';

            if (result.suspicious_patterns && result.suspicious_patterns.length > 0) {
                html += '<div class="suspicious-warning">';
                html += '⚠ <strong>Suspicious:</strong> ' + result.suspicious_patterns.join(', ');
                html += '</div>';
            }

            // Original
            const origDisplay = result.original.length > 100 ? result.original.substring(0, 100) + '...' : result.original;
            html += '<div class="layer">';
            html += '<div class="layer-label">Original:</div>';
            html += '<code>' + escapeHtml(origDisplay) + '</code>';
            html += '</div>';

            // Decoded layers
            if (result.decoded && result.decoded.length > 0) {
                result.decoded.forEach((decoded, layerIdx) => {
                    const decodedDisplay = decoded.length > 100 ? decoded.substring(0, 100) + '...' : decoded;
                    html += '<div class="layer">';
                    html += '<div class="layer-label">Layer ' + (layerIdx + 1) + ':</div>';
                    html += '<code>' + escapeHtml(decodedDisplay) + '</code>';
                    html += '</div>';
                });
            }

            html += '</div>';
        });

        // Store full results for rule generation
        window.deobfResults = results;
    } else {
        html += '<p>No encoded strings detected.</p>';
    }

    container.innerHTML = html;
}

// Toggle deobfuscation selection
function toggleDeobfSelection(checkbox, index) {
    if (checkbox.checked) {
        selectedDeobfuscated.push(index);
    } else {
        selectedDeobfuscated = selectedDeobfuscated.filter(i => i !== index);
    }
}

// Display IOCs with checkboxes
function displayIOCs(iocs) {
    const container = document.getElementById('iocs-content');
    let html = '';

    html += '<div style="margin-bottom: 20px;">';
    html += '<button class="btn-secondary" onclick="generateIOCRules()">Generate Rules from Selected IOCs</button>';
    html += '</div>';

    // URLs
    if (iocs.urls && iocs.urls.length > 0) {
        html += '<div class="ioc-section">';
        html += '<h4>◉ URLs (' + iocs.urls.length + ')</h4>';
        html += '<ul class="ioc-list">';
        iocs.urls.forEach((url, i) => {
            html += '<li>';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-type="urls" data-value="' + escapeHtml(url) + '" onchange="toggleIOCSelection(this, \'urls\', \'' + escapeHtml(url) + '\')">';
            html += escapeHtml(url);
            html += '</label>';
            html += '</li>';
        });
        html += '</ul></div>';
    }

    // IPs
    if (iocs.ips && iocs.ips.length > 0) {
        html += '<div class="ioc-section">';
        html += '<h4>◉ IP Addresses (' + iocs.ips.length + ')</h4>';
        html += '<ul class="ioc-list">';
        iocs.ips.forEach(ip => {
            html += '<li>';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-type="ips" data-value="' + ip + '" onchange="toggleIOCSelection(this, \'ips\', \'' + ip + '\')">';
            html += ip;
            html += '</label>';
            html += '</li>';
        });
        html += '</ul></div>';
    }

    // Domains
    if (iocs.domains && iocs.domains.length > 0) {
        html += '<div class="ioc-section">';
        html += '<h4>◉ Domains (' + iocs.domains.length + ')</h4>';
        html += '<ul class="ioc-list">';
        iocs.domains.forEach(domain => {
            html += '<li>';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-type="domains" data-value="' + domain + '" onchange="toggleIOCSelection(this, \'domains\', \'' + domain + '\')">';
            html += domain;
            html += '</label>';
            html += '</li>';
        });
        html += '</ul></div>';
    }

    // Registry Keys
    if (iocs.registry_keys && iocs.registry_keys.length > 0) {
        html += '<div class="ioc-section">';
        html += '<h4>◉ Registry Keys (' + iocs.registry_keys.length + ')</h4>';
        html += '<ul class="ioc-list">';
        iocs.registry_keys.forEach(key => {
            html += '<li>';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-type="registry_keys" data-value="' + escapeHtml(key) + '" onchange="toggleIOCSelection(this, \'registry_keys\', \'' + escapeHtml(key) + '\')">';
            html += escapeHtml(key);
            html += '</label>';
            html += '</li>';
        });
        html += '</ul></div>';
    }

    // Mutexes
    if (iocs.mutexes && iocs.mutexes.length > 0) {
        html += '<div class="ioc-section">';
        html += '<h4>◉ Mutexes (' + iocs.mutexes.length + ')</h4>';
        html += '<ul class="ioc-list">';
        iocs.mutexes.forEach(mutex => {
            html += '<li>';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-type="mutexes" data-value="' + escapeHtml(mutex) + '" onchange="toggleIOCSelection(this, \'mutexes\', \'' + escapeHtml(mutex) + '\')">';
            html += escapeHtml(mutex);
            html += '</label>';
            html += '</li>';
        });
        html += '</ul></div>';
    }

    // File Paths
    if (iocs.file_paths && iocs.file_paths.length > 0) {
        html += '<div class="ioc-section">';
        html += '<h4>◉ File Paths (' + iocs.file_paths.length + ')</h4>';
        html += '<ul class="ioc-list">';
        iocs.file_paths.forEach(path => {
            html += '<li>';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-type="file_paths" data-value="' + escapeHtml(path) + '" onchange="toggleIOCSelection(this, \'file_paths\', \'' + escapeHtml(path) + '\')">';
            html += escapeHtml(path);
            html += '</label>';
            html += '</li>';
        });
        html += '</ul></div>';
    }

    // Crypto Addresses
    if (iocs.crypto_addresses && iocs.crypto_addresses.length > 0) {
        html += '<div class="ioc-section">';
        html += '<h4>◉ Cryptocurrency Addresses (' + iocs.crypto_addresses.length + ')</h4>';
        html += '<ul class="ioc-list">';
        iocs.crypto_addresses.forEach(addr => {
            html += '<li>';
            html += '<label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">';
            html += '<input type="checkbox" class="ioc-checkbox" data-type="crypto_addresses" data-value="' + addr + '" onchange="toggleIOCSelection(this, \'crypto_addresses\', \'' + addr + '\')">';
            html += addr;
            html += '</label>';
            html += '</li>';
        });
        html += '</ul></div>';
    }

    if (!iocs.urls?.length && !iocs.ips?.length && !iocs.domains?.length &&
        !iocs.registry_keys?.length && !iocs.mutexes?.length && !iocs.file_paths?.length &&
        !iocs.crypto_addresses?.length) {
        html += '<p>No IOCs detected.</p>';
    }

    container.innerHTML = html;
}

// Toggle IOC selection
function toggleIOCSelection(checkbox, type, value) {
    if (checkbox.checked) {
        if (!selectedIOCs[type].includes(value)) {
            selectedIOCs[type].push(value);
        }
    } else {
        selectedIOCs[type] = selectedIOCs[type].filter(v => v !== value);
    }
}

// Generate custom rules from selected deobfuscated strings
async function generateCustomRules() {
    if (selectedDeobfuscated.length === 0) {
        alert('Please select at least one decoded sample');
        return;
    }

    const selectedStrings = selectedDeobfuscated.map(i => {
        const result = window.deobfResults[i];
        return result.decoded[result.decoded.length - 1] || result.original;
    });

    try {
        const response = await fetch('/generate-custom-rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                strings: selectedStrings,
                rule_name: currentResults.rule_name || 'Custom_Selection'
            })
        });

        const data = await response.json();

        // Show in modal or new tab
        showCustomRules(data.yara_rule, data.sigma_rule);
    } catch (error) {
        alert('Error generating rules: ' + error.message);
    }
}

// Generate rules from selected IOCs
async function generateIOCRules() {
    const hasSelection = Object.values(selectedIOCs).some(arr => arr.length > 0);

    if (!hasSelection) {
        alert('Please select at least one IOC');
        return;
    }

    try {
        const response = await fetch('/generate-ioc-rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                iocs: selectedIOCs,
                rule_name: currentResults.rule_name || 'Custom_IOC'
            })
        });

        const data = await response.json();
        showCustomRules(data.yara_rules, data.sigma_rules);
    } catch (error) {
        alert('Error generating IOC rules: ' + error.message);
    }
}

// Show custom generated rules
function showCustomRules(yaraRules, sigmaRules) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); z-index: 9999; display: flex; align-items: center; justify-content: center; padding: 20px;';

    const content = document.createElement('div');
    content.style.cssText = 'background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; max-width: 900px; max-height: 80vh; overflow-y: auto; padding: 30px;';

    content.innerHTML = `
        <h3 style="color: var(--accent-green); margin-bottom: 20px;">◆ Custom Generated Rules</h3>

        <div style="margin-bottom: 30px;">
            <h4 style="color: var(--accent-cyan);">YARA Rules</h4>
            ${typeof yaraRules === 'object' ?
                Object.entries(yaraRules).map(([key, rule]) => `
                    <div class="rule-download-section">
                        <h5>${key.toUpperCase()}</h5>
                        <pre><code>${escapeHtml(rule)}</code></pre>
                        <button class="btn-secondary" onclick="downloadRule('${key}.yar', \`${escapeHtml(rule)}\`)">Download ${key}.yar</button>
                    </div>
                `).join('') :
                `<pre><code>${escapeHtml(yaraRules)}</code></pre>
                 <button class="btn-secondary" onclick="downloadRule('custom.yar', \`${escapeHtml(yaraRules)}\`)">Download YARA</button>`
            }
        </div>

        <div style="margin-bottom: 30px;">
            <h4 style="color: var(--accent-cyan);">Sigma Rules</h4>
            ${typeof sigmaRules === 'object' ?
                Object.entries(sigmaRules).map(([key, rule]) => `
                    <div class="rule-download-section">
                        <h5>${key.toUpperCase()}</h5>
                        <pre><code>${escapeHtml(rule)}</code></pre>
                        <button class="btn-secondary" onclick="downloadRule('${key}.yml', \`${escapeHtml(rule)}\`)">Download ${key}.yml</button>
                    </div>
                `).join('') :
                `<pre><code>${escapeHtml(sigmaRules)}</code></pre>
                 <button class="btn-secondary" onclick="downloadRule('custom.yml', \`${escapeHtml(sigmaRules)}\`)">Download Sigma</button>`
            }
        </div>

        <button class="btn-primary" onclick="this.closest('[style*=fixed]').remove()">Close</button>
    `;

    modal.appendChild(content);
    document.body.appendChild(modal);

    // Close on background click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
}

// Display ATT&CK Mapping
function displayAttackMapping(mapping) {
    const container = document.getElementById('attack-content');

    if (!mapping.techniques || mapping.techniques.length === 0) {
        container.innerHTML = '<p>No ATT&CK techniques identified.</p>';
        return;
    }

    let html = '<table class="technique-table">';
    html += '<thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Confidence</th><th>Link</th></tr></thead>';
    html += '<tbody>';

    mapping.techniques.forEach(tech => {
        // Get confidence from confidence_scores dict or use match_count
        const confidence = mapping.confidence_scores && mapping.confidence_scores[tech.id]
            ? mapping.confidence_scores[tech.id] + '%'
            : (tech.match_count ? tech.match_count + ' matches' : 'Medium');

        html += '<tr>';
        html += '<td>' + tech.id + '</td>';
        html += '<td>' + tech.name + '</td>';
        html += '<td>' + tech.tactic + '</td>';
        html += '<td>' + confidence + '</td>';
        html += '<td><a href="https://attack.mitre.org/techniques/' + tech.id.replace('.', '/') + '/" target="_blank">View</a></td>';
        html += '</tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

// Display YARA rules with individual downloads
function displayYaraRules(mainRule, iocRules) {
    const container = document.getElementById('yara-content');
    let html = '';

    // Main catch-all rule
    html += '<div class="rule-download-section">';
    html += '<h4>◆ Main Detection Rule (Catch-All)</h4>';
    html += '<pre><code id="yara-rule">' + escapeHtml(mainRule) + '</code></pre>';
    html += '<button class="btn-secondary" onclick="downloadRule(\'main.yar\', document.getElementById(\'yara-rule\').textContent)">Download Main Rule</button>';
    html += '</div>';

    // Individual IOC rules
    if (iocRules && Object.keys(iocRules).length > 0) {
        html += '<h4 style="margin-top: 30px;">◆ IOC-Specific Rules</h4>';

        Object.entries(iocRules).forEach(([category, rule]) => {
            html += '<div class="rule-download-section">';
            html += '<h5>' + category.toUpperCase().replace('_', ' ') + '</h5>';
            html += '<pre><code class="ioc-yara-rule">' + escapeHtml(rule) + '</code></pre>';
            html += '<button class="btn-secondary" onclick="downloadRule(\'' + category + '.yar\', this.previousElementSibling.textContent)">Download ' + category + '.yar</button>';
            html += '</div>';
        });
    }

    container.innerHTML = html;
}

// Display Sigma rules with individual downloads
function displaySigmaRules(mainRule, iocRules) {
    const container = document.getElementById('sigma-content');
    let html = '';

    // Main catch-all rule
    html += '<div class="rule-download-section">';
    html += '<h4>◇ Main Detection Rule (Catch-All)</h4>';
    html += '<pre><code id="sigma-rule">' + escapeHtml(mainRule) + '</code></pre>';
    html += '<button class="btn-secondary" onclick="downloadRule(\'main.yml\', document.getElementById(\'sigma-rule\').textContent)">Download Main Rule</button>';
    html += '</div>';

    // Individual IOC rules
    if (iocRules && Object.keys(iocRules).length > 0) {
        html += '<h4 style="margin-top: 30px;">◇ IOC-Specific Rules</h4>';

        Object.entries(iocRules).forEach(([category, rule]) => {
            html += '<div class="rule-download-section">';
            html += '<h5>' + category.toUpperCase().replace('_', ' ') + '</h5>';
            html += '<pre><code class="ioc-sigma-rule">' + escapeHtml(rule) + '</code></pre>';
            html += '<button class="btn-secondary" onclick="downloadRule(\'' + category + '.yml\', this.previousElementSibling.textContent)">Download ' + category + '.yml</button>';
            html += '</div>';
        });
    }

    container.innerHTML = html;
}

// Display Report
function displayReport(report) {
    document.getElementById('report-content').innerHTML = '<pre style="white-space: pre-wrap;">' + escapeHtml(report) + '</pre>';
}

// Download rule helper
function downloadRule(filename, content) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// Tab switching
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(tabName + '-tab').classList.add('active');
    event.target.classList.add('active');
}

// HTML escape utility
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
