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
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const progressPreview = document.getElementById('progress-preview');

    // Generate session ID for progress tracking
    const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    formData.append('session_id', sessionId);

    // Hide upload section immediately
    const uploadSection = document.getElementById('upload-section');
    if (uploadSection) {
        uploadSection.style.display = 'none';
    }

    // Show loading and progress, hide results
    loadingDiv.style.display = 'block';
    resultsDiv.style.display = 'none';
    if (progressContainer) {
        progressContainer.style.display = 'block';
        progressBar.style.width = '0%';
        progressBar.style.transition = 'none'; // Reset transition
        progressText.textContent = 'Starting analysis...';
        progressPreview.textContent = ''; // Clear previous method chain
    }

    // Start listening for progress updates
    const eventSource = new EventSource(`/progress/${sessionId}`);

    let progressCompleted = false;
    let methodChain = []; // Track the chain of successful methods (reset for each upload)
    let updateQueue = []; // Queue for delayed updates (reset for each upload)
    let isProcessingQueue = false;
    let lastProgressValue = 0; // Track last progress to prevent backwards movement

    // Function to process queued updates with delay
    const processUpdateQueue = () => {
        if (isProcessingQueue || updateQueue.length === 0) {
            return;
        }

        isProcessingQueue = true;
        const update = updateQueue.shift();

        // Apply the update
        if (update.type === 'success') {
            methodChain.push(update.methodName);
            progressPreview.textContent = methodChain.join(' → ');
        } else if (update.type === 'complete') {
            progressPreview.textContent = methodChain.join(' → ');
        }

        // Update progress bar and text (only move forward, never backward)
        if (update.progress !== undefined) {
            const newProgress = Math.max(lastProgressValue, Math.min(update.progress, 100));
            if (newProgress > lastProgressValue) {
                progressBar.style.transition = 'width 0.5s ease-out';
                progressBar.style.width = `${newProgress}%`;
                lastProgressValue = newProgress;
            }
        }
        if (update.progressText) {
            progressText.textContent = update.progressText;
        }

        // Process next update after delay
        setTimeout(() => {
            isProcessingQueue = false;
            processUpdateQueue();
        }, 400); // 400ms delay between updates
    };

    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.status === 'complete') {
            eventSource.close();
            if (progressContainer) {
                // Animate to 100% smoothly
                progressBar.style.transition = 'width 1s ease-out';
                progressBar.style.width = '100%';
                progressText.textContent = 'Analysis complete!';
                progressCompleted = true;
            }
            return;
        }

        if (data.status === 'alive') {
            // Heartbeat - do nothing
            return;
        }

        // Queue progress updates for delayed display
        if (data.layer !== undefined && data.total_layers && progressContainer) {
            // data.layer can be decimal (e.g., 2.3 = layer 2, 30% through methods)
            const progress = (data.layer / data.total_layers) * 100;

            // Extract actual layer from virtual layer
            // Virtual layer uses strategy_index * max_depth + iteration
            // To get actual layer (1-6): take modulo and adjust
            const maxDepth = 6;
            let displayLayer = Math.ceil(data.layer);

            // Try to extract layer from message text first (most accurate)
            const layerMatch = data.method.match(/Layer (\d+)/);
            if (layerMatch) {
                displayLayer = parseInt(layerMatch[1]);
            } else {
                // For success messages without layer in text, calculate from virtual layer
                // Subtract 1, take modulo max_depth, add 1 back
                displayLayer = ((Math.ceil(data.layer) - 1) % maxDepth) + 1;
            }

            const progressTextValue = `${data.method} (${displayLayer}/${maxDepth})`;

            // Handle different update types
            if (data.method && data.method.includes('successful')) {
                // Successful decode - queue with progress bar update (only if progress increases)
                const methodName = data.method.replace('✓', '').replace('successful', '').trim();

                // Only queue if progress is moving forward
                if (progress > lastProgressValue || updateQueue.length === 0) {
                    updateQueue.push({
                        type: 'success',
                        methodName: methodName,
                        progress: progress,
                        progressText: `Layer ${displayLayer}/${maxDepth}`
                    });
                    processUpdateQueue();
                }
            } else if (data.method === 'Complete') {
                // Final completion
                updateQueue.push({
                    type: 'complete',
                    progress: 100,
                    progressText: 'Analysis complete!'
                });
                processUpdateQueue();
            }
            // Note: No longer showing "Trying" messages - they caused progress bar jumps
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

        // Debug logging
        console.log('Deobfuscation Results:', data.deobfuscation_results);
        console.log('All Deobfuscation Failed:', allDeobfuscationFailed);
        if (data.deobfuscation_results && data.deobfuscation_results.length > 0) {
            console.log('First result failed status:', data.deobfuscation_results[0].failed);
            console.log('First result failure_reason:', data.deobfuscation_results[0].failure_reason);
        }

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

        // Wait for progress bar to complete before showing results
        const showResults = () => {
            loadingDiv.style.display = 'none';

            // For failures, hide progress immediately before showing failure message
            // For success, hide progress with a delay for smooth transition
            if (allDeobfuscationFailed) {
                if (progressContainer) {
                    progressContainer.style.display = 'none';
                    console.log('Progress panel hidden immediately (failure case)');
                }
                // Small delay to let progress panel disappear, then prepare UI and show failure message
                setTimeout(() => {
                    console.log('Hiding UI elements due to complete deobfuscation failure');

                    // Hide upload section
                    const uploadSection = document.getElementById('upload-section');
                    if (uploadSection) {
                        uploadSection.style.display = 'none';
                        console.log('Upload section hidden');
                    }

                    // Hide "Analysis Results" heading
                    const resultsHeading = document.querySelector('#results > h2');
                    if (resultsHeading) {
                        resultsHeading.style.display = 'none';
                        console.log('Analysis Results heading hidden');
                    }

                    // Hide "Deobfuscation Results" heading inside the tab
                    const deobfHeading = document.querySelector('#deobfuscation-tab > h3');
                    if (deobfHeading) {
                        deobfHeading.style.display = 'none';
                        console.log('Deobfuscation Results heading hidden');
                    }

                    // Hide summary cards and tab navigation
                    const summaryCards = document.querySelector('.summary-cards');
                    const tabs = document.querySelector('.tabs');
                    if (summaryCards) {
                        summaryCards.style.display = 'none';
                        console.log('Summary cards hidden');
                    }
                    if (tabs) {
                        tabs.style.display = 'none';
                        console.log('Tab navigation hidden');
                    }

                    // Hide all tab content EXCEPT the deobfuscation tab
                    const tabContents = document.querySelectorAll('.tab-content');
                    tabContents.forEach(tab => {
                        // Keep deobfuscation-tab visible, hide all others
                        if (tab.id === 'deobfuscation-tab') {
                            tab.style.display = 'block';
                            console.log('Deobfuscation tab kept visible');
                        } else {
                            tab.style.display = 'none';
                            console.log('Tab hidden:', tab.id);
                        }
                    });

                    // Finally, show the failure message
                    resultsDiv.style.display = 'block';
                    console.log('Failure message displayed');
                }, 300);
            } else {
                // Success case - show results and fade out progress bar
                resultsDiv.style.display = 'block';
                if (progressContainer) {
                    // Fade out the progress bar after a delay
                    setTimeout(() => {
                        progressContainer.style.display = 'none';
                    }, 1500);
                }
            }
        };

        // If progress hasn't completed yet, wait for it
        if (!progressCompleted && progressContainer) {
            // Wait up to 3 seconds for progress to complete
            let waited = 0;
            const waitInterval = setInterval(() => {
                waited += 100;
                if (progressCompleted || waited >= 3000) {
                    clearInterval(waitInterval);
                    // Give user 2 seconds to see 100% completion
                    setTimeout(showResults, 2000);
                }
            }, 100);
        } else {
            // Progress already complete or no progress bar, show results after delay
            setTimeout(showResults, 2000);
        }

        // Hide upload form and conditionally show "New Analysis" button
        const uploadSection = document.getElementById('upload-section');
        const newAnalysisBtn = document.getElementById('new-analysis-btn');
        if (uploadSection && newAnalysisBtn) {
            uploadSection.style.display = 'none';
            // Only show "New Analysis" button if deobfuscation didn't completely fail
            // (When it fails, we show "Try Another File" button in the failure message instead)
            if (allDeobfuscationFailed) {
                newAnalysisBtn.style.display = 'none';
                console.log('New Analysis button hidden (deobfuscation failed)');
            } else {
                newAnalysisBtn.style.display = 'block';
                console.log('New Analysis button shown');
            }
        }

        // Scroll to results
        resultsDiv.scrollIntoView({ behavior: 'smooth' });

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
            title.textContent = '📄 String Analysis Details';
            html = generateStringsDetail();
            break;
        case 'decoded':
            title.textContent = '🔓 Deobfuscation Trace';
            html = generateDecodedDetail();
            break;
        case 'iocs':
            title.textContent = '🎯 IOC Breakdown';
            html = generateIOCsDetail();
            break;
        case 'techniques':
            title.textContent = '⚔️ ATT&CK Techniques Detail';
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
    let html = '<div class="detail-section">';
    
    // Stats
    html += '<div class="detail-stats">';
    html += `<p><strong>Total Unique Strings:</strong> ${currentResults.summary.strings}</p>`;
    html += `<p><strong>File:</strong> ${currentResults.filename || 'N/A'}</p>`;
    html += '</div>';
    
    // String categories breakdown
    if (currentResults.deobfuscation_stats) {
        html += '<h3>📊 String Analysis</h3>';
        html += '<div class="stats-grid">';
        html += `<div class="stat-item">
            <span class="stat-label">Encoded Strings Detected:</span>
            <span class="stat-value">${currentResults.deobfuscation_stats.successfully_decoded || 0}</span>
        </div>`;
        html += `<div class="stat-item">
            <span class="stat-label">Max Decoding Depth:</span>
            <span class="stat-value">${currentResults.deobfuscation_stats.max_depth || 0} layers</span>
        </div>`;
        // methods_used is an object with method names as keys and counts as values
        const methodsCount = currentResults.deobfuscation_stats.methods_used ?
            Object.keys(currentResults.deobfuscation_stats.methods_used).length : 0;
        html += `<div class="stat-item">
            <span class="stat-label">Decoding Methods Used:</span>
            <span class="stat-value">${methodsCount}</span>
        </div>`;
        html += '</div>';

        if (currentResults.deobfuscation_stats.methods_used && methodsCount > 0) {
            html += '<h4>🔧 Deobfuscation Methods Applied:</h4>';
            html += '<ul class="methods-list">';
            Object.entries(currentResults.deobfuscation_stats.methods_used).forEach(([method, count]) => {
                html += `<li><code>${escapeHtml(method)}</code> <span class="method-count">(${count}x)</span></li>`;
            });
            html += '</ul>';
        }
    }
    
    // Entropy info - only show if there are high entropy strings
    if (currentResults.analysis && currentResults.analysis.high_entropy_strings && currentResults.analysis.high_entropy_strings.length > 0) {
        html += '<h3>📈 Entropy Analysis</h3>';
        html += `<p><strong>High-Entropy Strings:</strong> ${currentResults.analysis.high_entropy_strings.length}</p>`;
        html += '<p class="hint">High entropy strings may indicate encryption, compression, or obfuscation</p>';
    }

    // Suspicious keywords - only show if keywords were found
    if (currentResults.analysis && currentResults.analysis.suspicious_keywords && currentResults.analysis.suspicious_keywords.length > 0) {
        html += '<h3>⚠️ Suspicious Keywords</h3>';
        html += `<p><strong>Keywords Found:</strong> ${currentResults.analysis.suspicious_keywords.length}</p>`;
        html += '<div class="keywords-list">';
        currentResults.analysis.suspicious_keywords.forEach(kw => {
            html += `<span class="keyword-badge">${escapeHtml(kw)}</span>`;
        });
        html += '</div>';
    }
    
    html += '</div>';
    return html;
}

function generateDecodedDetail() {
    let html = '<div class="detail-section">';
    
    if (!currentResults.deobfuscation_results || currentResults.deobfuscation_results.length === 0) {
        html += '<p class="no-data">No encoded strings were detected or decoded.</p>';
        html += '</div>';
        return html;
    }
    
    html += `<p class="detail-summary">Successfully decoded <strong>${currentResults.deobfuscation_stats.successfully_decoded}</strong> encoded string(s) with max depth of <strong>${currentResults.deobfuscation_stats.max_depth}</strong> layers.</p>`;
    
    currentResults.deobfuscation_results.forEach((result, index) => {
        html += `<div class="deobf-detail-item">`;
        html += `<h3>🔐 Encoded String #${index + 1}</h3>`;

        // Show failure message if deobfuscation failed
        if (result.failed) {
            html += '<div class="detail-subsection failure-notice">';
            html += '<h4>⚠️ Deobfuscation Failed</h4>';
            html += `<p class="failure-message"><strong>Reason:</strong> ${escapeHtml(result.failure_reason || 'Unknown error')}</p>`;
            if (result.quality_score !== undefined) {
                html += `<p><strong>Quality Score:</strong> ${result.quality_score.toFixed(2)} / 1.00</p>`;
            }
            if (result.strategy_used) {
                html += `<p><strong>Strategy Used:</strong> ${escapeHtml(result.strategy_used)}</p>`;
            }
            if (result.strategies_attempted && result.strategies_attempted.length > 1) {
                html += `<p><strong>Strategies Attempted:</strong> ${result.strategies_attempted.join(', ')}</p>`;
            }
            html += '</div>';
        } else {
            // Show success info
            if (result.quality_score !== undefined || result.strategy_used) {
                html += '<div class="detail-subsection success-notice">';
                html += '<h4>✓ Deobfuscation Success</h4>';
                if (result.quality_score !== undefined) {
                    html += `<p><strong>Quality Score:</strong> ${result.quality_score.toFixed(2)} / 1.00</p>`;
                }
                if (result.strategy_used) {
                    html += `<p><strong>Strategy Used:</strong> ${escapeHtml(result.strategy_used)}</p>`;
                }
                html += '</div>';
            }
        }

        // Show original
        html += '<div class="detail-subsection">';
        html += '<h4>Original (Encoded):</h4>';
        html += `<pre class="encoded-preview">${escapeHtml(result.original.substring(0, 100))}${result.original.length > 100 ? '...' : ''}</pre>`;
        html += '</div>';

        // Show trace
        if (result.trace && result.trace.length > 0) {
            html += '<div class="detail-subsection">';
            html += '<h4>🔍 Deobfuscation Trace:</h4>';
            html += '<div class="trace-timeline">';
            
            result.trace.forEach((step, i) => {
                const [method, success, preview] = step;
                const icon = success ? '✓' : '✗';
                const statusClass = success ? 'success' : 'failed';
                
                html += `<div class="trace-step ${statusClass}">`;
                html += `<span class="trace-icon">${icon}</span>`;
                html += `<span class="trace-method">${method}</span>`;
                html += `<div class="trace-preview">${escapeHtml(preview.substring(0, 80))}${preview.length > 80 ? '...' : ''}</div>`;
                html += `</div>`;
            });
            
            html += '</div>';
            html += '</div>';
        }
        
        // Show final plaintext (or failure warning)
        if (result.decoded && result.decoded.length > 0) {
            html += '<div class="detail-subsection">';
            if (result.failed) {
                html += '<h4>⚠️ Final Output (Likely Garbled/Incorrect):</h4>';
                html += `<pre class="plaintext-result" style="border-left: 4px solid #e74c3c; background: rgba(231, 76, 60, 0.05);">${escapeHtml(result.decoded[result.decoded.length - 1])}</pre>`;
                html += '<p style="color: #e74c3c; margin-top: 10px;">⚠️ This output appears to be garbled or incorrectly decoded. Consider enabling Smart Mode for better results.</p>';
            } else {
                html += '<h4>✓ Final Plaintext:</h4>';
                html += `<pre class="plaintext-result">${escapeHtml(result.decoded[result.decoded.length - 1])}</pre>`;
            }
            html += '</div>';
        }
        
        // Show suspicious patterns
        if (result.suspicious_patterns && result.suspicious_patterns.length > 0) {
            html += '<div class="detail-subsection">';
            html += '<h4>⚠️ Suspicious Patterns:</h4>';
            html += '<ul class="suspicious-list">';
            result.suspicious_patterns.forEach(pattern => {
                html += `<li>${escapeHtml(pattern)}</li>`;
            });
            html += '</ul>';
            html += '</div>';
        }
        
        html += `</div>`;
    });
    
    html += '</div>';
    return html;
}

function generateIOCsDetail() {
    let html = '<div class="detail-section">';

    const iocs = currentResults.iocs;
    const totalIOCs = (iocs.urls?.length || 0) + (iocs.ips?.length || 0) +
                     (iocs.domains?.length || 0) + (iocs.registry_keys?.length || 0) +
                     (iocs.mutexes?.length || 0) + (iocs.file_paths?.length || 0) +
                     (iocs.crypto_addresses?.length || 0);

    if (totalIOCs === 0) {
        html += '<div class="empty-state">';
        html += '<div class="empty-state-icon">🔍</div>';
        html += '<p>No Indicators of Compromise detected in this sample.</p>';
        html += '</div>';
        html += '</div>';
        return html;
    }

    const iocCategories = [
        { key: 'urls', icon: '🌐', label: 'URLs', color: '#e74c3c' },
        { key: 'ips', icon: '📡', label: 'IP Addresses', color: '#3498db' },
        { key: 'domains', icon: '🔗', label: 'Domains', color: '#9b59b6' },
        { key: 'registry_keys', icon: '🔑', label: 'Registry Keys', color: '#f39c12' },
        { key: 'mutexes', icon: '🔒', label: 'Mutexes', color: '#1abc9c' },
        { key: 'file_paths', icon: '📁', label: 'File Paths', color: '#34495e' },
        { key: 'crypto_addresses', icon: '💰', label: 'Crypto Addresses', color: '#e67e22' }
    ];

    const populatedCount = iocCategories.filter(cat => (iocs[cat.key]?.length || 0) > 0).length;
    html += `<p class="detail-summary">Detected <strong>${totalIOCs}</strong> Indicators of Compromise across <strong>${populatedCount}</strong> categor${populatedCount === 1 ? 'y' : 'ies'}.</p>`;

    iocCategories.forEach(cat => {
        const items = iocs[cat.key] || [];

        // Only show categories with items
        if (items.length > 0) {
            html += `<div class="ioc-category-detail">`;
            html += `<h3 style="color: ${cat.color}">${cat.icon} ${cat.label} <span class="count-badge">${items.length}</span></h3>`;
            html += '<ul class="ioc-list">';
            items.forEach(item => {
                html += `<li><code>${escapeHtml(item)}</code></li>`;
            });
            html += '</ul>';
            html += '</div>';
        }
    });

    html += '</div>';
    return html;
}

function generateTechniquesDetail() {
    let html = '<div class="detail-section">';
    
    const techniques = currentResults.attack_mapping?.techniques || [];
    
    if (techniques.length === 0) {
        html += '<p class="no-data">No ATT&CK techniques were mapped.</p>';
        html += '</div>';
        return html;
    }
    
    html += `<p class="detail-summary">Identified <strong>${techniques.length}</strong> potential MITRE ATT&CK technique(s).</p>`;
    
    // Group by tactic
    const tacticGroups = {};
    techniques.forEach(tech => {
        const tactic = tech.tactic || 'Unknown';
        if (!tacticGroups[tactic]) {
            tacticGroups[tactic] = [];
        }
        tacticGroups[tactic].push(tech);
    });
    
    Object.entries(tacticGroups).forEach(([tactic, techs]) => {
        html += `<div class="tactic-group">`;
        html += `<h3>📍 ${tactic} <span class="count-badge">${techs.length}</span></h3>`;

        // Sort techniques by confidence/match_count (high to low)
        const sortedTechs = techs.sort((a, b) => {
            const countA = a.match_count || 0;
            const countB = b.match_count || 0;
            return countB - countA; // Descending order
        });

        sortedTechs.forEach(tech => {
            // Map confidence based on match_count
            let confidenceLevel = 'low';
            const matchCount = tech.match_count || 0;
            if (matchCount >= 5) confidenceLevel = 'high';
            else if (matchCount >= 2) confidenceLevel = 'medium';

            html += `<div class="technique-detail-card">`;
            html += `<div class="technique-header">`;
            html += `<div>`;
            html += `<div class="technique-name">${escapeHtml(tech.name || 'Unknown')}</div>`;
            html += `<div class="technique-id">${tech.id || 'N/A'}</div>`;
            html += `</div>`;
            html += `<span class="confidence-badge ${confidenceLevel}">${confidenceLevel}</span>`;
            html += `</div>`;

            html += `<div class="technique-description">`;
            html += `Match count: <strong>${matchCount}</strong>`;
            html += `</div>`;

            html += `<div class="technique-footer">`;
            html += `<span class="technique-tactic">Tactic: ${escapeHtml(tech.tactic || 'Unknown')}</span>`;
            html += `<a href="https://attack.mitre.org/techniques/${tech.id}/" target="_blank" rel="noopener" class="technique-link">View in ATT&CK Framework ↗</a>`;
            html += `</div>`;

            html += `</div>`;
        });

        html += `</div>`;
    });
    
    html += '</div>';
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
