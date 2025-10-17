// Veriscope Web Interface JavaScript

let currentResults = null;
window.analysisData = null; // Store analysis data for deferred display (make it explicitly global)
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
    const progressContainer = document.getElementById('progress-container');

    // Generate session ID for progress tracking
    const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    formData.append('session_id', sessionId);

    // Hide upload section immediately
    const uploadSection = document.getElementById('upload-section');
    if (uploadSection) {
        uploadSection.style.display = 'none';
    }

    // Check if auto-show results is enabled
    const autoShowResults = document.getElementById('auto-show-results').checked;

    // Show loading, progress (if manual review), and hide results
    loadingDiv.classList.remove('fade-out'); // Reset fade animation if re-running
    resultsDiv.style.display = 'none';

    // Clear previous activity feed and reset stats cards
    const activityFeed = document.getElementById('activity-feed');
    const viewResultsBtn = document.getElementById('view-results-btn');
    const statStrategy = document.getElementById('stat-strategy');
    const statMethod = document.getElementById('stat-method');
    const statLayers = document.getElementById('stat-layers');

    if (activityFeed) {
        activityFeed.innerHTML = '<div class="activity-item info"><span class="icon">◆</span><span>Starting analysis...</span></div>';
    }
    if (viewResultsBtn) {
        viewResultsBtn.style.display = 'none';
    }
    // Reset stats cards
    if (statStrategy) statStrategy.textContent = 'balanced';
    if (statMethod) statMethod.textContent = '—';
    if (statLayers) statLayers.textContent = '0';

    // Show appropriate UI based on checkbox
    if (progressContainer) {
        progressContainer.classList.remove('slide-up'); // Reset slide animation

        if (autoShowResults) {
            // Auto-show mode: Show only spinner, hide activity feed
            loadingDiv.style.display = 'block';
            progressContainer.style.display = 'none';
        } else {
            // Manual review mode: Show both spinner AND activity feed side-by-side
            loadingDiv.style.display = 'block';
            progressContainer.style.display = 'block';
        }
    } else {
        loadingDiv.style.display = 'block';
    }

    // Start listening for progress updates
    const eventSource = new EventSource(`/progress/${sessionId}`);
    let progressCompleted = false;
    let analysisData = null; // Store data for later display
    let currentLayerCount = 0;

    // Helper function to update stats cards
    function updateStatsCards(message) {
        const statStrategy = document.getElementById('stat-strategy');
        const statMethod = document.getElementById('stat-method');
        const statLayers = document.getElementById('stat-layers');

        // Extract strategy/preset from message
        if (message.includes('Preset:')) {
            const presetMatch = message.match(/Preset:\s*(\w+)/);
            if (presetMatch && statStrategy) {
                statStrategy.textContent = presetMatch[1];
            }
        } else if (message.includes('Strategy:')) {
            const strategyMatch = message.match(/Strategy:\s*(.+?)(?:\s|$)/);
            if (strategyMatch && statStrategy) {
                const strategyName = strategyMatch[1].replace(/🔄|⚙|📦|◈/g, '').trim();
                if (strategyName && !strategyName.includes('Layer')) {
                    statStrategy.textContent = strategyName;
                }
            }
        }

        // Extract method from successful decode messages
        if (message.includes('successful')) {
            const methodMatch = message.match(/✓\s*(\w+)\s+successful/);
            if (methodMatch && statMethod) {
                statMethod.textContent = methodMatch[1];
            }

            // Increment layer count on successful decode
            currentLayerCount++;
            if (statLayers) {
                statLayers.textContent = currentLayerCount.toString();
            }
        }

        // Extract layer info from "Layer X" format as fallback
        const layerMatch = message.match(/Layer (\d+)/);
        if (layerMatch) {
            const layerNum = parseInt(layerMatch[1]);
            if (layerNum > currentLayerCount) {
                currentLayerCount = layerNum;
                if (statLayers) {
                    statLayers.textContent = currentLayerCount.toString();
                }
            }
        }
    }

    // Helper function to add activity item
    function addActivityItem(message, type = 'info') {
        const activityFeed = document.getElementById('activity-feed');
        if (!activityFeed) return;

        const item = document.createElement('div');
        item.className = `activity-item ${type}`;

        let icon = '→';
        if (type === 'success') icon = '✓';
        else if (type === 'complete') icon = '✓';
        else if (type === 'status') icon = '◈';
        else if (type === 'info') icon = '◆';

        item.innerHTML = `<span class="icon">${icon}</span><span>${escapeHtml(message)}</span>`;
        activityFeed.appendChild(item);

        // Auto-scroll to bottom
        activityFeed.scrollTop = activityFeed.scrollHeight;

        // Update stats cards based on message
        updateStatsCards(message);
    }

    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.status === 'complete') {
            eventSource.close();
            progressCompleted = true;
            addActivityItem('Analysis complete - ready to view results', 'complete');

            // Fade out spinner
            setTimeout(() => {
                loadingDiv.classList.add('fade-out');

                // After fade out completes, hide spinner
                setTimeout(() => {
                    loadingDiv.style.display = 'none';
                    // If auto-show is enabled, activity feed will be hidden by response handler
                    // If manual review, activity feed stays visible (already showing)
                }, 500); // Match fadeOut duration
            }, 100); // Small delay before starting fade

            return;
        }

        if (data.status === 'alive') {
            return; // Heartbeat - ignore
        }

        // Process messages with method information
        if (data.method) {
            // Determine message type
            if (data.method.includes('successful')) {
                // Successful decode
                addActivityItem(data.method, 'success');
            } else if (data.method.includes('Strategy:') || data.method.includes('Preset:') ||
                       data.method.includes('rotation') || data.method.includes('alternative')) {
                // Strategy/preset change notification
                addActivityItem(data.method, 'status');
            } else if (data.method.includes('Trying')) {
                // Skip "Trying" messages to reduce noise (optional)
                // Uncomment next line if you want to show them:
                // addActivityItem(data.method, 'info');
            } else {
                // Other informational messages
                addActivityItem(data.method, 'info');
            }
        }
    };

    eventSource.onerror = () => {
        eventSource.close();
    };

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
        console.log('Received data from /analyze:', data);

        // Store in global variable
        window.analysisData = data;
        console.log('Stored in window.analysisData:', window.analysisData);

        // Check if all deobfuscation results failed
        const allDeobfuscationFailed = data.deobfuscation_results &&
                                       data.deobfuscation_results.length > 0 &&
                                       data.deobfuscation_results.every(r => r.failed === true);

        console.log('All deobfuscation failed:', allDeobfuscationFailed);

        // Always hide loading spinner
        loadingDiv.style.display = 'none';

        // Check if user wants auto-show or manual review
        console.log('autoShowResults:', autoShowResults);
        if (autoShowResults || allDeobfuscationFailed) {
            // Auto-show results OR failed deobfuscation - hide activity feed and show results immediately
            console.log('Auto-showing results or failed decode - hiding activity feed');
            if (progressContainer) {
                progressContainer.style.display = 'none';
                progressContainer.classList.remove('slide-up'); // Remove animation class
            }
            showAnalysisResults();
        } else {
            // Manual review mode AND successful decode - activity feed already visible, just show button
            console.log('Manual review mode - keeping activity feed visible with View Results button');
            const viewResultsBtn = document.getElementById('view-results-btn');
            if (viewResultsBtn) {
                viewResultsBtn.style.display = 'block';
                console.log('View Results button displayed');
            } else {
                console.error('View Results button element not found!');
            }
        }

    } catch (error) {
        eventSource.close();
        alert('Error: ' + error.message);
        loadingDiv.style.display = 'none';
        if (progressContainer) {
            progressContainer.style.display = 'none';
        }
        // Show upload section again on error
        const uploadSection = document.getElementById('upload-section');
        if (uploadSection) {
            uploadSection.style.display = 'block';
        }
    }
});

// Function to display analysis results (make it globally accessible)
window.showAnalysisResults = function() {
    console.log('showAnalysisResults called');
    console.log('window.analysisData:', window.analysisData);

    if (!window.analysisData) {
        console.error('No window.analysisData available!');
        alert('No analysis data available. Please run an analysis first.');
        return;
    }

    const data = window.analysisData;
    const resultsDiv = document.getElementById('results');
    const progressContainer = document.getElementById('progress-container');

    console.log('resultsDiv:', resultsDiv);
    console.log('progressContainer:', progressContainer);

    // Hide the activity feed when showing results
    if (progressContainer) {
        progressContainer.style.display = 'none';
    }

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

    // Check if all deobfuscation results failed
    const allDeobfuscationFailed = data.deobfuscation_results &&
                                   data.deobfuscation_results.length > 0 &&
                                   data.deobfuscation_results.every(r => r.failed === true);

    // Populate Deobfuscation tab
    if (data.deobfuscation_stats) {
        displayDeobfuscation(data.deobfuscation_stats, data.deobfuscation_results, allDeobfuscationFailed);
    }

    // Only populate other tabs if deobfuscation didn't completely fail
    if (!allDeobfuscationFailed) {
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
    }

    // Hide progress container
    if (progressContainer) {
        progressContainer.style.display = 'none';
    }

    // Handle UI based on results
    if (allDeobfuscationFailed) {
        // Hide upload section
        const uploadSection = document.getElementById('upload-section');
        if (uploadSection) {
            uploadSection.style.display = 'none';
        }

        // Hide "Analysis Results" heading
        const resultsHeading = document.querySelector('#results > h2');
        if (resultsHeading) {
            resultsHeading.style.display = 'none';
        }

        // Hide "Deobfuscation Results" heading inside the tab
        const deobfHeading = document.querySelector('#deobfuscation-tab > h3');
        if (deobfHeading) {
            deobfHeading.style.display = 'none';
        }

        // Hide summary cards and tab navigation
        const summaryCards = document.querySelector('.summary-cards');
        const tabs = document.querySelector('.tabs');
        if (summaryCards) {
            summaryCards.style.display = 'none';
        }
        if (tabs) {
            tabs.style.display = 'none';
        }

        // Hide all tab content EXCEPT the deobfuscation tab
        const tabContents = document.querySelectorAll('.tab-content');
        tabContents.forEach(tab => {
            if (tab.id === 'deobfuscation-tab') {
                tab.style.display = 'block';
            } else {
                tab.style.display = 'none';
            }
        });
    }

    // Show results
    resultsDiv.style.display = 'block';

    // Hide upload form and conditionally show "New Analysis" button
    const uploadSection = document.getElementById('upload-section');
    const newAnalysisBtn = document.getElementById('new-analysis-btn');
    if (uploadSection && newAnalysisBtn) {
        uploadSection.style.display = 'none';
        // Only show "New Analysis" button if deobfuscation didn't completely fail
        if (allDeobfuscationFailed) {
            newAnalysisBtn.style.display = 'none';
        } else {
            newAnalysisBtn.style.display = 'block';
        }
    }

    // Scroll to results
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
};

// Display Deobfuscation Results with checkboxes
function displayDeobfuscation(stats, results, allFailed = false) {
    const container = document.getElementById('deobfuscation-content');
    let html = '';

    console.log('displayDeobfuscation called with allFailed:', allFailed);
    console.log('Results:', results);

    // If all deobfuscation failed, show prominent failure message
    if (allFailed) {
        console.log('Rendering failure message...');

        // Main failure message box
        html += '<div class="failure-notice" style="background: rgba(231, 76, 60, 0.1); border: 2px solid #e74c3c; border-radius: 8px; padding: 30px; text-align: center; margin: 20px auto; max-width: 800px;">';
        html += '<h2 style="color: #e74c3c; margin: 0 0 15px 0; font-size: 1.8em;">⚠️ Decoding Failed</h2>';
        html += '<p style="font-size: 1.1em; margin-bottom: 20px; color: #ecf0f1;">All deobfuscation attempts produced garbled or low-quality output.</p>';

        // Show failure reasons and attempted decoders
        if (results && results.length > 0) {
            try {
                console.log('Processing failure reasons, results:', results);

                const uniqueReasons = [...new Set(results.map(r => r.failure_reason).filter(r => r))];

                // Collect all attempted methods from trace (more reliable than methods_used)
                const allMethods = [];
                results.forEach(r => {
                    console.log('Result trace:', r.trace);
                    console.log('Result methods_used:', r.methods_used);

                    // Get methods from trace (shows what was actually attempted)
                    if (r.trace && r.trace.length > 0) {
                        r.trace.forEach(traceItem => {
                            const [method, success, preview] = traceItem;
                            if (success && method !== 'no_match' && method !== 'cycle' && method !== 'too_short' && method !== 'timeout' && method !== 'size_limit') {
                                allMethods.push(method);
                            }
                        });
                    }
                });
                const uniqueMethods = [...new Set(allMethods)];
                console.log('Unique methods extracted:', uniqueMethods);

                if (uniqueReasons.length > 0 || uniqueMethods.length > 0) {
                    html += '<div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 4px; margin-bottom: 20px; text-align: left;">';

                    // Show reasons (no bullets)
                    if (uniqueReasons.length > 0) {
                        html += '<div style="margin-bottom: 12px;">';
                        html += '<strong style="color: #ecf0f1;">Reason:</strong><br>';
                        html += '<span style="color: #ecf0f1; margin-left: 0;">' + escapeHtml(uniqueReasons[0]) + '</span>';
                        html += '</div>';
                    }

                    // Show attempted decoders
                    if (uniqueMethods.length > 0) {
                        html += '<div>';
                        html += '<strong style="color: #ecf0f1;">Decoders Attempted:</strong><br>';
                        html += '<span style="color: #ecf0f1; margin-left: 0; font-family: monospace;">' + escapeHtml(uniqueMethods.join(', ')) + '</span>';
                        html += '</div>';
                    } else {
                        console.warn('No decoders found in trace');
                    }

                    html += '</div>';
                }
            } catch (e) {
                console.error('Error rendering failure reasons:', e);
            }
        }

        // Buttons
        html += '<div style="margin-top: 20px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">';
        html += '<button onclick="resetForNewAnalysis()" class="btn-primary" style="font-size: 1.1em; padding: 15px 30px;">📁 Try Another File</button>';
        html += '<button onclick="showFailedResults()" class="btn-secondary" style="font-size: 1.0em; padding: 15px 30px;">🔍 Show Failed Results</button>';
        html += '</div>';
        html += '</div>'; // Close failure notice

        // Collapsed failed results section
        html += '<div id="failed-results-section" style="display: none; margin-top: 20px;">';
        html += '<h3 style="color: #e74c3c;">Failed Decoding Attempts</h3>';
    }

    // Stats summary (show for both success and failure, but collapsed if all failed)
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
            html += '<div class="deobf-sample-header" style="cursor: pointer;" onclick="toggleDeobfDetails(' + i + ')">';
            html += '<div style="display: flex; align-items: center; gap: 10px;">';
            html += '<input type="checkbox" class="deobf-checkbox" data-index="' + i + '" onchange="event.stopPropagation(); toggleDeobfSelection(this, ' + i + ')" onclick="event.stopPropagation();">';
            html += '<strong>Sample ' + (i + 1) + '</strong>';
            html += '<span style="color: var(--accent-cyan);">(' + result.layers + ' layers)</span>';
            if (result.suspicious_patterns && result.suspicious_patterns.length > 0) {
                html += '<span style="color: var(--accent-warning);">⚠ Suspicious</span>';
            }
            html += '</div>';
            html += '<span class="expand-icon" id="expand-icon-' + i + '">▼ Show Details</span>';
            html += '</div>';

            // Final result (always visible)
            if (result.decoded && result.decoded.length > 0) {
                const finalDecoded = result.decoded[result.decoded.length - 1];
                const finalDisplay = finalDecoded.length > 200 ? finalDecoded.substring(0, 200) + '...' : finalDecoded;

                if (result.failed) {
                    // Show warning for failed deobfuscation
                    html += '<div class="final-result" style="border-left: 4px solid #e74c3c; background: rgba(231, 76, 60, 0.05);">';
                    html += '<div class="layer-label" style="color: #e74c3c;">⚠️ Final Output (Likely Garbled):</div>';
                    html += '<code>' + escapeHtml(finalDisplay) + '</code>';
                    html += '<div style="color: #e74c3c; font-size: 0.9em; margin-top: 8px; padding: 8px; background: rgba(231, 76, 60, 0.1); border-radius: 4px;">';
                    html += '⚠️ <strong>Warning:</strong> ' + escapeHtml(result.failure_reason || 'Output appears to be garbled or incorrectly decoded');
                    html += '<br><small>Quality Score: ' + (result.quality_score || 0).toFixed(2) + ' / 1.00</small>';
                    html += '</div>';
                    html += '</div>';
                } else {
                    // Show success for good deobfuscation
                    html += '<div class="final-result">';
                    html += '<div class="layer-label">✓ Final Decoded Result:</div>';
                    html += '<code>' + escapeHtml(finalDisplay) + '</code>';
                    if (result.quality_score !== undefined) {
                        html += '<div style="color: var(--accent-green); font-size: 0.85em; margin-top: 5px;">';
                        html += '✓ Quality Score: ' + result.quality_score.toFixed(2) + ' / 1.00';
                        html += '</div>';
                    }
                    html += '</div>';
                }
            }

            // Detailed layers (collapsed by default)
            html += '<div class="deobf-details" id="deobf-details-' + i + '" style="display: none; margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--border-color);">';

            if (result.suspicious_patterns && result.suspicious_patterns.length > 0) {
                html += '<div class="suspicious-warning">';
                html += '⚠ <strong>Suspicious Patterns:</strong> ' + result.suspicious_patterns.join(', ');
                html += '</div>';
            }

            // Original
            const origDisplay = result.original.length > 150 ? result.original.substring(0, 150) + '...' : result.original;
            html += '<div class="layer">';
            html += '<div class="layer-label">Original (Encoded):</div>';
            html += '<code>' + escapeHtml(origDisplay) + '</code>';
            html += '</div>';

            // All decoded layers
            if (result.decoded && result.decoded.length > 0) {
                result.decoded.forEach((decoded, layerIdx) => {
                    const decodedDisplay = decoded.length > 150 ? decoded.substring(0, 150) + '...' : decoded;
                    html += '<div class="layer">';
                    html += '<div class="layer-label">Layer ' + (layerIdx + 1) + ' Decoded:</div>';
                    html += '<code>' + escapeHtml(decodedDisplay) + '</code>';
                    html += '</div>';
                });
            }

            html += '</div>'; // Close deobf-details
            html += '</div>'; // Close deobf-sample
        });

        // Store full results for rule generation
        window.deobfResults = results;
    } else {
        html += '<p>No encoded strings detected.</p>';
    }

    // Close failed results section if it was opened
    if (allFailed) {
        html += '</div>'; // Close failed-results-section
    }

    container.innerHTML = html;
}

// Show/hide failed results section
function showFailedResults() {
    const section = document.getElementById('failed-results-section');
    if (section) {
        if (section.style.display === 'none') {
            section.style.display = 'block';
        } else {
            section.style.display = 'none';
        }
    }
}

// Toggle deobfuscation details
function toggleDeobfDetails(index) {
    const details = document.getElementById('deobf-details-' + index);
    const icon = document.getElementById('expand-icon-' + index);

    if (details.style.display === 'none') {
        details.style.display = 'block';
        icon.textContent = '▲ Hide Details';
    } else {
        details.style.display = 'none';
        icon.textContent = '▼ Show Details';
    }
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

// ============================================================================
// DETAIL MODAL FUNCTIONS
// ============================================================================

function showDetailModal(type) {
    if (!currentResults) return;
    
    const modal = document.getElementById('detail-modal');
    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-body');
    
    let html = '';
    
    switch(type) {
        case 'strings':
            title.textContent = 'String Analysis Details';
            html = generateStringsDetail();
            break;
        case 'decoded':
            title.textContent = 'Deobfuscation Trace';
            html = generateDecodedDetail();
            break;
        case 'iocs':
            title.textContent = 'IOC Breakdown';
            html = generateIOCsDetail();
            break;
        case 'techniques':
            title.textContent = 'ATT&CK Techniques Detail';
            html = generateTechniquesDetail();
            break;
    }
    
    body.innerHTML = html;
    modal.style.display = 'block';
}

function closeModal(event) {
    const modal = document.getElementById('detail-modal');
    if (!event || event.target === modal || event.target.classList.contains('close')) {
        modal.style.display = 'none';
    }
}

function generateStringsDetail() {
    let html = '';

    // Overview Section
    html += '<div class="modal-section">';
    html += '<h3>Overview</h3>';
    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">';
    html += `<div style="background: rgba(0, 212, 255, 0.1); padding: 15px; border-radius: 6px; border-left: 3px solid var(--accent-cyan);">
        <div style="font-size: 0.85em; color: var(--text-secondary); margin-bottom: 5px;">Total Strings</div>
        <div style="font-size: 2em; font-weight: bold; color: var(--accent-cyan);">${currentResults.summary.strings}</div>
    </div>`;
    html += `<div style="background: rgba(0, 255, 136, 0.1); padding: 15px; border-radius: 6px; border-left: 3px solid var(--accent-green);">
        <div style="font-size: 0.85em; color: var(--text-secondary); margin-bottom: 5px;">Source File</div>
        <div style="font-size: 1em; font-weight: 600; color: var(--accent-green); word-break: break-all;">${escapeHtml(currentResults.filename || 'N/A')}</div>
    </div>`;
    html += '</div>';
    html += '</div>';

    // Deobfuscation Stats Section
    if (currentResults.deobfuscation_stats) {
        const methodsCount = currentResults.deobfuscation_stats.methods_used ?
            Object.keys(currentResults.deobfuscation_stats.methods_used).length : 0;

        html += '<div class="modal-section">';
        html += '<h3>Deobfuscation Summary</h3>';
        html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 15px;">';

        html += `<div style="display: flex; align-items: center; gap: 10px; padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
            <div style="font-size: 1.8em;">◆</div>
            <div>
                <div style="font-size: 0.8em; color: var(--text-secondary);">Decoded Strings</div>
                <div style="font-size: 1.4em; font-weight: bold; color: var(--accent-green);">${currentResults.deobfuscation_stats.successfully_decoded || 0}</div>
            </div>
        </div>`;

        html += `<div style="display: flex; align-items: center; gap: 10px; padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
            <div style="font-size: 1.8em;">◇</div>
            <div>
                <div style="font-size: 0.8em; color: var(--text-secondary);">Max Depth</div>
                <div style="font-size: 1.4em; font-weight: bold; color: var(--accent-cyan);">${currentResults.deobfuscation_stats.max_depth || 0} layers</div>
            </div>
        </div>`;

        html += `<div style="display: flex; align-items: center; gap: 10px; padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
            <div style="font-size: 1.8em;">◈</div>
            <div>
                <div style="font-size: 0.8em; color: var(--text-secondary);">Methods Used</div>
                <div style="font-size: 1.4em; font-weight: bold; color: var(--accent-green);">${methodsCount}</div>
            </div>
        </div>`;

        html += '</div>';

        // Show methods breakdown if available
        if (currentResults.deobfuscation_stats.methods_used && methodsCount > 0) {
            html += '<div style="margin-top: 20px;">';
            html += '<h4 style="color: var(--accent-cyan); font-size: 1em; margin-bottom: 12px;">Methods Applied</h4>';
            html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
            Object.entries(currentResults.deobfuscation_stats.methods_used).forEach(([method, count]) => {
                html += `<span class="modal-stat">${escapeHtml(method)} <span style="opacity: 0.7;">×${count}</span></span>`;
            });
            html += '</div>';
            html += '</div>';
        }
        html += '</div>';
    }

    // Entropy Analysis Section - only show if data exists
    if (currentResults.analysis && currentResults.analysis.high_entropy_strings && currentResults.analysis.high_entropy_strings.length > 0) {
        html += '<div class="modal-section">';
        html += '<h3>Entropy Analysis</h3>';
        html += `<p style="margin: 12px 0;"><strong style="color: var(--accent-cyan);">${currentResults.analysis.high_entropy_strings.length}</strong> high-entropy string(s) detected</p>`;
        html += '<p style="font-size: 0.9em; color: var(--text-secondary); font-style: italic; margin: 0;">High entropy may indicate encryption, compression, or obfuscation</p>';
        html += '</div>';
    }

    // Suspicious Keywords Section - only show if data exists
    if (currentResults.analysis && currentResults.analysis.suspicious_keywords && currentResults.analysis.suspicious_keywords.length > 0) {
        html += '<div class="modal-section">';
        html += '<h3>Suspicious Keywords</h3>';
        html += `<p style="margin: 12px 0 15px 0;"><strong style="color: var(--accent-cyan);">${currentResults.analysis.suspicious_keywords.length}</strong> suspicious keyword(s) found</p>`;
        html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
        currentResults.analysis.suspicious_keywords.forEach(kw => {
            html += `<span style="background: rgba(231, 76, 60, 0.15); color: #e74c3c; padding: 6px 12px; border-radius: 4px; font-size: 0.9em; border: 1px solid rgba(231, 76, 60, 0.3);">${escapeHtml(kw)}</span>`;
        });
        html += '</div>';
        html += '</div>';
    }

    return html;
}

function generateDecodedDetail() {
    if (!currentResults.deobfuscation_results || currentResults.deobfuscation_results.length === 0) {
        return `<div class="modal-section" style="text-align: center; padding: 40px;">
            <div style="font-size: 4em; opacity: 0.3; margin-bottom: 15px;">◇</div>
            <p style="font-size: 1.1em; color: var(--text-secondary);">No encoded strings were detected or decoded.</p>
        </div>`;
    }

    let html = '';

    // Calculate successful vs failed counts
    const successfulCount = currentResults.deobfuscation_results.filter(r => !r.failed).length;
    const failedCount = currentResults.deobfuscation_results.filter(r => r.failed).length;
    const totalCount = currentResults.deobfuscation_results.length;

    // Overview section with success/failure breakdown
    html += '<div class="modal-section">';
    html += '<h3>Overview</h3>';
    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">';

    // Successful decodes card
    html += `<div style="background: rgba(0, 255, 136, 0.1); padding: 15px; border-radius: 6px; border-left: 3px solid var(--accent-green);">
        <div style="font-size: 0.85em; color: var(--text-secondary); margin-bottom: 5px;">✓ Successful Decodes</div>
        <div style="font-size: 2em; font-weight: bold; color: var(--accent-green);">${successfulCount}</div>
    </div>`;

    // Failed decodes card (only show if there are failures)
    if (failedCount > 0) {
        html += `<div style="background: rgba(231, 76, 60, 0.1); padding: 15px; border-radius: 6px; border-left: 3px solid #e74c3c;">
            <div style="font-size: 0.85em; color: var(--text-secondary); margin-bottom: 5px;">✗ Failed Decodes</div>
            <div style="font-size: 2em; font-weight: bold; color: #e74c3c;">${failedCount}</div>
        </div>`;
    }

    // Max depth card
    html += `<div style="background: rgba(0, 212, 255, 0.1); padding: 15px; border-radius: 6px; border-left: 3px solid var(--accent-cyan);">
        <div style="font-size: 0.85em; color: var(--text-secondary); margin-bottom: 5px;">Max Depth</div>
        <div style="font-size: 2em; font-weight: bold; color: var(--accent-cyan);">${currentResults.deobfuscation_stats.max_depth} layers</div>
    </div>`;

    html += '</div>';
    html += '</div>';

    currentResults.deobfuscation_results.forEach((result, index) => {
        // Add status indicator to section
        const statusIcon = result.failed ? '✗' : '✓';
        const statusColor = result.failed ? '#e74c3c' : '#1e8449'; // Much darker green for better contrast with white text
        const statusText = result.failed ? 'Failed' : 'Success';

        html += `<div class="modal-section" style="${result.failed ? '' : 'border-left-color: var(--accent-green);'}">`;
        html += `<h3 style="display: flex; align-items: center; gap: 10px;">
            <span>Encoded String #${index + 1}</span>
            <span style="background: ${statusColor}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.7em; font-weight: 600;">${statusIcon} ${statusText}</span>
        </h3>`;

        // Prominently display methods used for successful deobfuscation
        if (!result.failed && result.methods_used && result.methods_used.length > 0) {
            html += '<div style="background: linear-gradient(135deg, rgba(0, 255, 136, 0.15), rgba(0, 212, 255, 0.15)); border: 1px solid var(--accent-green); border-radius: 8px; padding: 20px; margin-bottom: 20px;">';
            html += '<h4 style="color: var(--accent-green); margin: 0 0 12px 0; font-size: 1.1em;">Deobfuscation Methods Used:</h4>';
            html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
            result.methods_used.forEach((method, idx) => {
                html += `<span class="modal-stat">${escapeHtml(method)}</span>`;
                if (idx < result.methods_used.length - 1) {
                    html += '<span style="color: var(--accent-cyan); font-size: 1.2em;">→</span>';
                }
            });
            html += '</div>';
            html += '</div>';
        }

        // Show failure message if deobfuscation failed
        if (result.failed) {
            html += '<div style="background: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 8px; padding: 20px; margin-bottom: 20px;">';
            html += '<h4 style="color: #e74c3c; margin: 0 0 12px 0;">Deobfuscation Failed</h4>';
            html += `<p style="margin: 0;"><strong>Reason:</strong> ${escapeHtml(result.failure_reason || 'Unknown error')}</p>`;
            if (result.quality_score !== undefined) {
                html += `<p style="margin: 8px 0 0 0;"><strong>Quality Score:</strong> ${result.quality_score.toFixed(2)} / 1.00</p>`;
            }
            if (result.strategy_used) {
                html += `<p style="margin: 8px 0 0 0;"><strong>Strategy Used:</strong> ${escapeHtml(result.strategy_used)}</p>`;
            }
            if (result.strategies_attempted && result.strategies_attempted.length > 1) {
                html += `<p style="margin: 8px 0 0 0;"><strong>Strategies Attempted:</strong> ${result.strategies_attempted.join(', ')}</p>`;
            }
            html += '</div>';
        } else {
            // Show success info
            if (result.quality_score !== undefined) {
                html += `<p style="margin-bottom: 15px;"><strong>Quality Score:</strong> <span style="color: var(--accent-green);">${result.quality_score.toFixed(2)} / 1.00</span></p>`;
            }
            if (result.strategy_used) {
                html += `<p style="margin-bottom: 15px;"><strong>Strategy Used:</strong> ${escapeHtml(result.strategy_used)}</p>`;
            }
        }

        // Show original
        html += '<h4 style="margin-top: 20px; margin-bottom: 10px;">Original (Encoded):</h4>';
        html += `<pre style="background: var(--bg-secondary); padding: 12px; border-radius: 6px; border-left: 3px solid var(--accent-cyan); overflow-x: auto;">${escapeHtml(result.original.substring(0, 200))}${result.original.length > 200 ? '...' : ''}</pre>`;

        // Show trace with highlighting for final plaintext
        if (result.trace && result.trace.length > 0) {
            html += '<h4 style="margin-top: 20px; margin-bottom: 15px;">Deobfuscation Trace:</h4>';

            // Get the final decoded result for comparison
            const finalPlaintext = result.decoded && result.decoded.length > 0 ? result.decoded[result.decoded.length - 1] : null;

            result.trace.forEach((step, i) => {
                const [method, success, preview] = step;
                const isLastSuccess = success && i === result.trace.length - 1;
                const isFinalPlaintextMatch = finalPlaintext && preview === finalPlaintext;

                // Highlight if this is the final plaintext result
                const highlightClass = (isLastSuccess || isFinalPlaintextMatch) && !result.failed ? 'final-plaintext-row' : '';

                html += `<div class="trace-step ${success ? 'success' : 'failed'} ${highlightClass}" style="display: flex; align-items: start; gap: 12px; padding: 12px; margin-bottom: 10px; border-radius: 6px; background: ${highlightClass ? 'linear-gradient(135deg, rgba(0, 255, 136, 0.1), rgba(0, 212, 255, 0.1))' : 'var(--bg-secondary)'}; border: 1px solid ${highlightClass ? 'var(--accent-green)' : 'var(--border-color)'}; ${highlightClass ? 'box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);' : ''}">`;
                html += `<span style="color: ${success ? 'var(--accent-green)' : 'var(--accent-danger)'}; font-size: 1.2em; min-width: 20px;">${success ? '◆' : '◇'}</span>`;
                html += `<div style="flex: 1;">`;
                html += `<div style="color: var(--accent-cyan); font-weight: bold; margin-bottom: 6px;">${escapeHtml(method)}${highlightClass ? ' → Final Result' : ''}</div>`;
                html += `<code style="display: block; background: var(--bg-primary); padding: 8px; border-radius: 4px; font-size: 0.85em; overflow-x: auto; white-space: pre-wrap; word-break: break-all;">${escapeHtml(preview.substring(0, 150))}${preview.length > 150 ? '...' : ''}</code>`;
                html += `</div>`;
                html += `</div>`;
            });
        }

        // Show final plaintext
        if (result.decoded && result.decoded.length > 0) {
            html += '<h4 style="margin-top: 25px; margin-bottom: 10px;">Final Plaintext:</h4>';
            if (result.failed) {
                html += `<pre style="background: rgba(231, 76, 60, 0.05); padding: 15px; border-radius: 6px; border-left: 4px solid #e74c3c; overflow-x: auto; white-space: pre-wrap; word-break: break-all;">${escapeHtml(result.decoded[result.decoded.length - 1])}</pre>`;
                html += '<p style="color: #e74c3c; margin-top: 10px; font-size: 0.9em;">This output appears to be garbled or incorrectly decoded.</p>';
            } else {
                // Add green glow highlighting to match the trace row
                html += `<pre style="background: linear-gradient(135deg, rgba(0, 255, 136, 0.1), rgba(0, 212, 255, 0.1)); padding: 15px; border-radius: 6px; border: 1px solid var(--accent-green); border-left: 4px solid var(--accent-green); box-shadow: 0 0 15px rgba(0, 255, 136, 0.3); overflow-x: auto; white-space: pre-wrap; word-break: break-all;">${escapeHtml(result.decoded[result.decoded.length - 1])}</pre>`;
            }
        }

        // Show suspicious patterns
        if (result.suspicious_patterns && result.suspicious_patterns.length > 0) {
            html += '<h4 style="margin-top: 20px; margin-bottom: 10px;">Suspicious Patterns:</h4>';
            html += '<ul class="icon-list">';
            result.suspicious_patterns.forEach(pattern => {
                html += `<li>${escapeHtml(pattern)}</li>`;
            });
            html += '</ul>';
        }

        html += `</div>`;
    });

    return html;
}

function generateIOCsDetail() {
    const iocs = currentResults.iocs;
    const totalIOCs = (iocs.urls?.length || 0) + (iocs.ips?.length || 0) +
                     (iocs.domains?.length || 0) + (iocs.registry_keys?.length || 0) +
                     (iocs.mutexes?.length || 0) + (iocs.file_paths?.length || 0) +
                     (iocs.crypto_addresses?.length || 0);

    if (totalIOCs === 0) {
        return `<div class="modal-section" style="text-align: center; padding: 40px;">
            <div style="font-size: 4em; opacity: 0.3; margin-bottom: 15px;">◇</div>
            <p style="font-size: 1.1em; color: var(--text-secondary);">No Indicators of Compromise detected in this sample.</p>
        </div>`;
    }

    const iocCategories = [
        { key: 'urls', icon: '◆', label: 'URLs', color: '#e74c3c', description: 'Web addresses' },
        { key: 'ips', icon: '◆', label: 'IP Addresses', color: '#3498db', description: 'Network endpoints' },
        { key: 'domains', icon: '◆', label: 'Domains', color: '#9b59b6', description: 'Domain names' },
        { key: 'registry_keys', icon: '◆', label: 'Registry Keys', color: '#f39c12', description: 'Windows registry' },
        { key: 'mutexes', icon: '◆', label: 'Mutexes', color: '#1abc9c', description: 'Mutex objects' },
        { key: 'file_paths', icon: '◆', label: 'File Paths', color: '#34495e', description: 'File system paths' },
        { key: 'crypto_addresses', icon: '◆', label: 'Crypto Addresses', color: '#e67e22', description: 'Cryptocurrency' }
    ];

    const populatedCount = iocCategories.filter(cat => (iocs[cat.key]?.length || 0) > 0).length;

    let html = '';

    // Overview section
    html += '<div class="modal-section">';
    html += '<h3>Overview</h3>';
    html += `<p style="font-size: 1.1em; margin: 15px 0;">Detected <strong style="color: var(--accent-cyan);">${totalIOCs}</strong> indicator(s) across <strong style="color: var(--accent-green);">${populatedCount}</strong> categor${populatedCount === 1 ? 'y' : 'ies'}</p>`;
    html += '</div>';

    // IOC Categories
    iocCategories.forEach(cat => {
        const items = iocs[cat.key] || [];

        if (items.length > 0) {
            html += `<div class="modal-section">`;
            html += `<h3 style="color: ${cat.color}; display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 1.2em;">${cat.icon}</span>
                <span>${cat.label}</span>
                <span style="background: ${cat.color}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600;">${items.length}</span>
            </h3>`;
            html += `<p style="font-size: 0.9em; color: var(--text-secondary); margin: 8px 0 15px 0; font-style: italic;">${cat.description}</p>`;

            html += '<div style="background: var(--bg-secondary); border-radius: 6px; padding: 15px; max-height: 300px; overflow-y: auto;">';
            html += '<ul class="icon-list" style="margin: 0;">';
            items.forEach(item => {
                html += `<li style="margin-bottom: 8px;"><code style="background: var(--bg-primary); padding: 4px 8px; border-radius: 3px; font-size: 0.9em;">${escapeHtml(item)}</code></li>`;
            });
            html += '</ul>';
            html += '</div>';
            html += '</div>';
        }
    });

    return html;
}

function generateTechniquesDetail() {
    const techniques = currentResults.attack_mapping?.techniques || [];

    if (techniques.length === 0) {
        return `<div class="modal-section" style="text-align: center; padding: 40px;">
            <div style="font-size: 4em; opacity: 0.3; margin-bottom: 15px;">◎</div>
            <p style="font-size: 1.1em; color: var(--text-secondary);">No ATT&CK techniques were mapped for this sample.</p>
        </div>`;
    }

    let html = '';

    // Overview section
    html += '<div class="modal-section">';
    html += '<h3>Overview</h3>';
    html += `<p style="font-size: 1.1em; margin: 15px 0;">Identified <strong style="color: var(--accent-cyan);">${techniques.length}</strong> potential MITRE ATT&CK technique(s)</p>`;
    html += '</div>';

    // Group by tactic
    const tacticGroups = {};
    techniques.forEach(tech => {
        const tactic = tech.tactic || 'Unknown';
        if (!tacticGroups[tactic]) {
            tacticGroups[tactic] = [];
        }
        tacticGroups[tactic].push(tech);
    });

    // Tactic color mapping
    const tacticColors = {
        'Initial Access': '#e74c3c',
        'Execution': '#e67e22',
        'Persistence': '#f39c12',
        'Privilege Escalation': '#f1c40f',
        'Defense Evasion': '#1abc9c',
        'Credential Access': '#16a085',
        'Discovery': '#3498db',
        'Lateral Movement': '#2980b9',
        'Collection': '#9b59b6',
        'Command and Control': '#8e44ad',
        'Exfiltration': '#34495e',
        'Impact': '#c0392b'
    };

    Object.entries(tacticGroups).forEach(([tactic, techs]) => {
        const tacticColor = tacticColors[tactic] || 'var(--accent-cyan)';

        html += `<div class="modal-section">`;
        html += `<h3 style="color: ${tacticColor}; display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 1.2em;">◆</span>
            <span>${tactic}</span>
            <span style="background: ${tacticColor}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600;">${techs.length}</span>
        </h3>`;

        // Sort techniques by confidence/match_count (high to low)
        const sortedTechs = techs.sort((a, b) => {
            const countA = a.match_count || 0;
            const countB = b.match_count || 0;
            return countB - countA;
        });

        sortedTechs.forEach(tech => {
            const matchCount = tech.match_count || 0;
            let confidenceLevel = 'low';
            let confidenceColor = '#95a5a6';
            if (matchCount >= 5) {
                confidenceLevel = 'high';
                confidenceColor = '#27ae60';
            } else if (matchCount >= 2) {
                confidenceLevel = 'medium';
                confidenceColor = '#f39c12';
            }

            html += `<div style="background: var(--bg-secondary); border-radius: 6px; padding: 15px; margin-bottom: 12px; border-left: 3px solid ${tacticColor};">`;

            html += `<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">`;
            html += `<div style="flex: 1;">`;
            html += `<div style="font-size: 1.1em; font-weight: 600; color: var(--accent-cyan); margin-bottom: 4px;">${escapeHtml(tech.name || 'Unknown')}</div>`;
            html += `<div style="font-size: 0.9em; color: var(--text-secondary); font-family: monospace;">${tech.id || 'N/A'}</div>`;
            html += `</div>`;
            html += `<span style="background: ${confidenceColor}; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: 600; text-transform: uppercase;">${confidenceLevel}</span>`;
            html += `</div>`;

            html += `<div style="display: flex; justify-content: space-between; align-items: center;">`;
            html += `<span style="font-size: 0.9em; color: var(--text-secondary);">Matches: <strong style="color: var(--accent-green);">${matchCount}</strong></span>`;
            html += `<a href="https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/" target="_blank" rel="noopener" style="color: var(--accent-cyan); text-decoration: none; font-size: 0.9em; display: flex; align-items: center; gap: 5px;">
                <span>View Details</span>
                <span>↗</span>
            </a>`;
            html += `</div>`;

            html += `</div>`;
        });

        html += `</div>`;
    });

    return html;
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
    }
});

// Handle "New Analysis" button click
function resetForNewAnalysis() {
    // Hide results and new analysis button
    document.getElementById('results').style.display = 'none';
    document.getElementById('new-analysis-btn').style.display = 'none';

    // Show upload section
    document.getElementById('upload-section').style.display = 'block';

    // Restore "Analysis Results" heading
    const resultsHeading = document.querySelector('#results > h2');
    if (resultsHeading) resultsHeading.style.display = 'block';

    // Restore "Deobfuscation Results" heading
    const deobfHeading = document.querySelector('#deobfuscation-tab > h3');
    if (deobfHeading) deobfHeading.style.display = 'block';

    // Restore tabs and summary cards (in case they were hidden due to failure)
    const summaryCards = document.querySelector('.summary-cards');
    const tabs = document.querySelector('.tabs');
    if (summaryCards) summaryCards.style.display = 'grid';
    if (tabs) tabs.style.display = 'flex';

    // BUGFIX: Clear progress bar and method chain from previous analysis
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const progressPreview = document.getElementById('progress-preview');
    if (progressContainer) {
        progressContainer.style.display = 'none';
    }
    if (progressBar) {
        progressBar.style.width = '0%';
    }
    if (progressText) {
        progressText.textContent = 'Starting analysis...';
    }
    if (progressPreview) {
        progressPreview.textContent = ''; // Clear method chain from previous analysis
    }

    // Reset form
    document.getElementById('upload-form').reset();

    // Clear current results
    currentResults = null;
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

    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}
