/*
SecuDataExtractor - JavaScript
Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
*/

// Global variables
let scrapingInterval;
let currentFilename = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializeForm();
    initializeRangeSlider();
    loadDatasets();
});

// Navigation functionality
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.sidebar .nav-link');
    const sections = document.querySelectorAll('.content-section');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetSection = this.dataset.section;
            
            // Update active nav link
            navLinks.forEach(nl => nl.classList.remove('active'));
            this.classList.add('active');
            
            // Show target section
            sections.forEach(section => {
                section.classList.remove('active');
            });
            
            const targetElement = document.getElementById(targetSection + '-section');
            if (targetElement) {
                targetElement.classList.add('active');
            }
            
            // Load datasets when datasets section is shown
            if (targetSection === 'datasets') {
                loadDatasets();
            }
        });
    });
}

// Form initialization
function initializeForm() {
    const form = document.getElementById('scraper-form');
    const startButton = document.getElementById('start-scraping-btn');
    
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        startScraping();
    });
}

// Harvest mode dropdown functionality
function initializeRangeSlider() {
    const harvestModeSelect = document.getElementById('max-entries');
    const valueDisplay = document.getElementById('max-entries-value');
    
    harvestModeSelect.addEventListener('change', function() {
        const selectedOption = this.options[this.selectedIndex];
        if (this.value === 'unlimited') {
            valueDisplay.textContent = 'Unlimited';
        } else {
            valueDisplay.textContent = selectedOption.text;
        }
    });
}

// Start scraping process
function startScraping() {
    const form = document.getElementById('scraper-form');
    const formData = new FormData(form);
    
    // Get selected sources
    const sources = Array.from(formData.getAll('sources'));
    const maxEntriesValue = formData.get('max_entries') || document.getElementById('max-entries').value;
    const maxEntries = maxEntriesValue === 'unlimited' ? 'unlimited' : parseInt(maxEntriesValue);
    
    if (sources.length === 0) {
        showAlert('Please select at least one data source.', 'warning');
        return;
    }
    
    console.log('Selected harvest mode:', maxEntriesValue, 'Processed value:', maxEntries);
    
    // Prepare request data
    const requestData = {
        sources: sources,
        max_entries_per_source: maxEntriesValue  // Send raw value to match backend expectations
    };
    
    // Show loading state
    const startButton = document.getElementById('start-scraping-btn');
    startButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
    startButton.disabled = true;
    
    // Send request to start scraping
    fetch('/start_scraping', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showAlert(data.error, 'danger');
            resetStartButton();
        } else {
            currentFilename = data.filename;
            showAlert('Scraping started successfully!', 'success');
            
            // Switch to progress section
            document.querySelector('[data-section="progress"]').click();
            
            // Start monitoring progress
            startProgressMonitoring();
        }
    })
    .catch(error => {
        showAlert('Error starting scraping: ' + error.message, 'danger');
        resetStartButton();
    });
}

// Start progress monitoring
function startProgressMonitoring() {
    const progressBar = document.getElementById('progress-bar');
    const statusBadge = document.getElementById('status-badge');
    const currentSourceSpan = document.getElementById('current-source');
    const elapsedTimeSpan = document.getElementById('elapsed-time');
    const totalEntriesSpan = document.getElementById('total-entries');
    const errorCountSpan = document.getElementById('error-count');
    const errorLog = document.getElementById('error-log');
    const completionActions = document.getElementById('completion-actions');
    
    // Update status badge
    statusBadge.textContent = 'Running';
    statusBadge.className = 'badge bg-primary';
    
    // Clear any existing interval
    if (scrapingInterval) {
        clearInterval(scrapingInterval);
    }
    
    // Start polling for status updates
    scrapingInterval = setInterval(() => {
        fetch('/status')
            .then(response => response.json())
            .then(status => {
                // Update progress bar
                const progress = status.progress || 0;
                progressBar.style.width = progress + '%';
                progressBar.textContent = progress + '%';
                
                // Update status badge
                if (status.running) {
                    statusBadge.textContent = 'Running';
                    statusBadge.className = 'badge bg-primary';
                    progressBar.classList.add('progress-bar-striped', 'progress-bar-animated');
                } else if (progress === 100) {
                    statusBadge.textContent = 'Complete';
                    statusBadge.className = 'badge bg-success';
                    progressBar.classList.remove('progress-bar-striped', 'progress-bar-animated');
                    
                    // Show completion actions
                    completionActions.style.display = 'block';
                    
                    // Setup download and preview buttons
                    setupCompletionActions();
                    
                    // Stop monitoring
                    clearInterval(scrapingInterval);
                    resetStartButton();
                } else {
                    statusBadge.textContent = 'Stopped';
                    statusBadge.className = 'badge bg-warning';
                    progressBar.classList.remove('progress-bar-striped', 'progress-bar-animated');
                    resetStartButton();
                }
                
                // Update other fields
                currentSourceSpan.textContent = status.current_source || '-';
                elapsedTimeSpan.textContent = status.elapsed_time || '-';
                totalEntriesSpan.textContent = status.total_entries || '0';
                errorCountSpan.textContent = status.errors ? status.errors.length : '0';
                
                // Update error log
                if (status.errors && status.errors.length > 0) {
                    let errorHtml = '';
                    status.errors.forEach(error => {
                        errorHtml += `<div class="error-item">${error}</div>`;
                    });
                    errorLog.innerHTML = errorHtml;
                } else {
                    errorLog.innerHTML = '<p class="text-muted">No errors to display</p>';
                }
            })
            .catch(error => {
                console.error('Error fetching status:', error);
            });
    }, 2000); // Poll every 2 seconds
}

// Setup completion action buttons
function setupCompletionActions() {
    const downloadBtn = document.getElementById('download-btn');
    const previewBtn = document.getElementById('preview-btn');
    
    if (currentFilename) {
        downloadBtn.onclick = () => {
            window.location.href = `/download/${currentFilename}`;
        };
        
        previewBtn.onclick = () => {
            previewDataset(currentFilename);
        };
    }
}

// Preview dataset in modal
function previewDataset(filename) {
    const modal = new bootstrap.Modal(document.getElementById('previewModal'));
    const previewContent = document.getElementById('preview-content');
    
    // Show loading
    previewContent.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    modal.show();
    
    // Fetch preview data
    fetch(`/preview/${filename}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                previewContent.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            let html = `<div class="mb-3"><strong>Showing first ${data.preview.length} entries (${data.total_lines} total)</strong></div>`;
            
            data.preview.forEach((entry, index) => {
                html += `
                    <div class="card mb-3">
                        <div class="card-header bg-light">
                            <small class="text-muted">Entry ${index + 1}</small>
                        </div>
                        <div class="card-body">
                            <div class="mb-2">
                                <strong class="text-primary">Instruction:</strong>
                                <div class="p-2 bg-light rounded mt-1">${escapeHtml(entry.instruction)}</div>
                            </div>
                            <div class="mb-2">
                                <strong class="text-info">Input:</strong>
                                <div class="p-2 bg-light rounded mt-1">${escapeHtml(entry.input.substring(0, 300))}${entry.input.length > 300 ? '...' : ''}</div>
                            </div>
                            <div>
                                <strong class="text-success">Output:</strong>
                                <div class="p-2 bg-light rounded mt-1">${escapeHtml(entry.output.substring(0, 300))}${entry.output.length > 300 ? '...' : ''}</div>
                            </div>
                        </div>
                    </div>
                `;
            });
            
            previewContent.innerHTML = html;
        })
        .catch(error => {
            previewContent.innerHTML = `<div class="alert alert-danger">Error loading preview: ${error.message}</div>`;
        });
}

// Load and display datasets
function loadDatasets() {
    const datasetsList = document.getElementById('datasets-list');
    
    // Show loading
    datasetsList.innerHTML = `
        <div class="text-center">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading datasets...</p>
        </div>
    `;
    
    fetch('/datasets')
        .then(response => response.json())
        .then(data => {
            if (data.datasets.length === 0) {
                datasetsList.innerHTML = `
                    <div class="text-center text-muted">
                        <i class="fas fa-database fa-3x mb-3"></i>
                        <h5>No datasets found</h5>
                        <p>Generate your first dataset using the scraper configuration.</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            data.datasets.forEach(dataset => {
                const fileSize = formatFileSize(dataset.size);
                html += `
                    <div class="dataset-item">
                        <div class="dataset-title">
                            <i class="fas fa-file-alt"></i> ${dataset.filename}
                        </div>
                        <div class="dataset-meta">
                            <span><i class="fas fa-calendar"></i> Created: ${dataset.created}</span>
                            <span class="ms-3"><i class="fas fa-weight-hanging"></i> Size: ${fileSize}</span>
                        </div>
                        <div class="dataset-actions">
                            <button class="btn btn-primary btn-sm" onclick="window.location.href='/download/${dataset.filename}'">
                                <i class="fas fa-download"></i> Download
                            </button>
                            <button class="btn btn-outline-secondary btn-sm" onclick="previewDataset('${dataset.filename}')">
                                <i class="fas fa-eye"></i> Preview
                            </button>
                        </div>
                    </div>
                `;
            });
            
            datasetsList.innerHTML = html;
        })
        .catch(error => {
            datasetsList.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i> Error loading datasets: ${error.message}
                </div>
            `;
        });
}

// Reset start button to original state
function resetStartButton() {
    const startButton = document.getElementById('start-scraping-btn');
    startButton.innerHTML = '<i class="fas fa-play"></i> Start Scraping';
    startButton.disabled = false;
}

// Show alert messages
function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Utility functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Handle page unload
window.addEventListener('beforeunload', function() {
    if (scrapingInterval) {
        clearInterval(scrapingInterval);
    }
});
