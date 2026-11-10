/**
 * WebSecure Inspector - Popup Script
 */

console.log('🎨 Popup script loaded');

// DOM Elements
const scoreElement = document.getElementById('score');
const ratingElement = document.getElementById('rating');
const rescanBtn = document.getElementById('rescan-btn');
const scanStatus = document.getElementById('scan-status');
const resultsContainer = document.getElementById('results-container');
const successMessage = document.getElementById('success-message');
const scanTimeElement = document.getElementById('scan-time');

const mixedContentCount = document.getElementById('mixed-content-count');
const unsafeLinksCount = document.getElementById('unsafe-links-count');
const insecureStorageCount = document.getElementById('insecure-storage-count');
const cspCount = document.getElementById('csp-count');

const mixedContentDetails = document.getElementById('mixed-content-details');
const unsafeLinksDetails = document.getElementById('unsafe-links-details');
const insecureStorageDetails = document.getElementById('insecure-storage-details');
const cspDetails = document.getElementById('csp-details');

// Initialize
document.addEventListener('DOMContentLoaded', loadResults);
rescanBtn.addEventListener('click', handleRescan);

// Category headers expand and collapse. Inline onclick is blocked in extension pages
// so the handlers are attached here.
document.querySelectorAll('.category-header[data-category]').forEach((header) => {
  header.addEventListener('click', () => {
    toggleCategory(header.getAttribute('data-category'));
  });
});

// Load Results
async function loadResults() {
  console.log('📥 Loading results...');
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      showError('Unable to access tab');
      return;
    }
    
    chrome.runtime.sendMessage({
      type: 'GET_RESULTS',
      tabId: tab.id
    }, (response) => {
      if (chrome.runtime.lastError) {
        showError('Failed to load results');
        return;
      }
      
      if (response.results) {
        displayResults(response.results);
      } else if (response.error) {
        showError(response.error);
      }
    });
    
  } catch (error) {
    showError('Error occurred');
  }
}

// Handle Rescan
async function handleRescan() {
  console.log('🔄 Rescan requested');
  showLoading();
  rescanBtn.disabled = true;
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    chrome.runtime.sendMessage({
      type: 'REQUEST_SCAN',
      tabId: tab.id
    }, (response) => {
      rescanBtn.disabled = false;
      
      if (response.status === 'success' && response.results) {
        displayResults(response.results);
      } else {
        showError(response.message || 'Scan failed');
      }
    });
    
  } catch (error) {
    rescanBtn.disabled = false;
    showError('Rescan failed');
  }
}

// Display Results
function displayResults(results) {
  console.log('📊 Displaying results');
  
  scanStatus.style.display = 'none';
  resultsContainer.style.display = 'block';
  
  displayScore(results.score, results.rating);
  displayMixedContent(results.mixedContent || []);
  displayUnsafeLinks(results.unsafeLinks || []);
  displayInsecureStorage(results.insecureStorage || []);
  displayCSPViolations(results.cspViolations || [], results.cspStatus);
  
  if (results.score >= 90) {
    successMessage.style.display = 'block';
  } else {
    successMessage.style.display = 'none';
  }
  
  if (results.scanTimestamp) {
    const date = new Date(results.scanTimestamp);
    scanTimeElement.textContent = `Last scan: ${date.toLocaleTimeString()}`;
  }
}

// Display Score
function displayScore(score, rating) {
  scoreElement.textContent = score;
  ratingElement.textContent = rating.toUpperCase();
  
  scoreElement.className = 'score';
  
  if (rating === 'Excellent') scoreElement.classList.add('excellent');
  else if (rating === 'Good') scoreElement.classList.add('good');
  else if (rating === 'Fair') scoreElement.classList.add('fair');
  else scoreElement.classList.add('poor');
}

// Display Mixed Content
function displayMixedContent(issues) {
  const count = issues.length;
  mixedContentCount.textContent = count === 0 ? '✓' : count;
  mixedContentCount.className = count === 0 ? 'issue-count zero' : 'issue-count';
  
  if (count === 0) {
    mixedContentDetails.innerHTML = '<div class="empty-state">✓ No issues</div>';
    document.querySelector('#mixed-content-section .severity-icon').className = 'severity-icon severity-ok';
    document.querySelector('#mixed-content-section .severity-icon').textContent = '✓';
  } else {
    mixedContentDetails.innerHTML = issues.map(issue => `
      <div class="issue-card high">
        <div class="issue-title">⚠️ ${escapeHtml(issue.message)}</div>
        <div class="issue-url">${escapeHtml(issue.url)}</div>
        <div class="issue-description">
          HTTP resources on HTTPS pages can be intercepted by attackers.
        </div>
      </div>
    `).join('');
  }
}

// Display Unsafe Links
function displayUnsafeLinks(issues) {
  const count = issues.length;
  unsafeLinksCount.textContent = count === 0 ? '✓' : count;
  unsafeLinksCount.className = count === 0 ? 'issue-count zero' : 'issue-count';
  
  if (count === 0) {
    unsafeLinksDetails.innerHTML = '<div class="empty-state">✓ No issues</div>';
    document.querySelector('#unsafe-links-section .severity-icon').className = 'severity-icon severity-ok';
    document.querySelector('#unsafe-links-section .severity-icon').textContent = '✓';
  } else {
    unsafeLinksDetails.innerHTML = issues.map(issue => `
      <div class="issue-card medium">
        <div class="issue-title">⚠️ ${escapeHtml(issue.message)}</div>
        <div class="issue-url">${escapeHtml(issue.url)}</div>
        <div class="issue-description">
          Links with target="_blank" should include rel="noopener noreferrer".
        </div>
      </div>
    `).join('');
  }
}

// Display Insecure Storage
function displayInsecureStorage(issues) {
  const count = issues.length;
  insecureStorageCount.textContent = count === 0 ? '✓' : count;
  insecureStorageCount.className = count === 0 ? 'issue-count zero' : 'issue-count';
  
  if (count === 0) {
    insecureStorageDetails.innerHTML = '<div class="empty-state">✓ No issues</div>';
    document.querySelector('#insecure-storage-section .severity-icon').className = 'severity-icon severity-ok';
    document.querySelector('#insecure-storage-section .severity-icon').textContent = '✓';
  } else {
    insecureStorageDetails.innerHTML = issues.map(issue => `
      <div class="issue-card critical">
        <div class="issue-title">🔴 ${escapeHtml(issue.message)}</div>
        <div class="issue-url">
          Storage: ${escapeHtml(issue.storageType)}<br>
          Key: ${escapeHtml(issue.key)}
        </div>
        <div class="issue-description">
          Sensitive data in storage is exposed to XSS attacks.
        </div>
      </div>
    `).join('');
  }
}

// Display CSP
const CSP_ADVICE = {
  'missing': "Without a CSP the browser runs any script that gets into the page. Add a Content-Security-Policy header, for example default-src 'self'.",
  'report-only': 'Problems are only logged and nothing is blocked. Send the policy as Content-Security-Policy to enforce it.',
  'no-script-rule': 'Add a default-src or script-src directive so the browser knows which scripts to trust.',
  'unsafe-inline': "Inline scripts are a common route for XSS attacks. Remove 'unsafe-inline' and move scripts into files, or use a nonce.",
  'unsafe-eval': "eval turns text into running code. Remove 'unsafe-eval' from the policy.",
  'wildcard': "Any site can supply scripts to this page. Replace the wildcard with 'self' and the exact sites you load scripts from."
};

function displayCSPViolations(issues, status) {
  const count = issues.length;
  const icon = document.querySelector('#csp-section .severity-icon');

  if (status === 'unreadable' || status === 'skipped') {
    cspCount.textContent = '?';
    cspCount.className = 'issue-count zero';
    cspDetails.innerHTML = `<div class="empty-state">${status === 'skipped'
      ? 'Not checked. This page was not loaded from a web server.'
      : 'Not checked. The CSP header for this page could not be read.'}</div>`;
    return;
  }

  cspCount.textContent = count === 0 ? '✓' : count;
  cspCount.className = count === 0 ? 'issue-count zero' : 'issue-count';

  if (count === 0) {
    cspDetails.innerHTML = '<div class="empty-state">✓ No issues</div>';
    if (icon) {
      icon.className = 'severity-icon severity-ok';
      icon.textContent = '✓';
    }
  } else {
    cspDetails.innerHTML = issues.map(issue => `
      <div class="issue-card high">
        <div class="issue-title">⚠️ ${escapeHtml(issue.message)}</div>
        <div class="issue-url">${escapeHtml(issue.evidence)}</div>
        <div class="issue-description">
          ${escapeHtml(CSP_ADVICE[issue.check] || 'Review the Content Security Policy for this page.')}
        </div>
      </div>
    `).join('');
  }
}

// Toggle Category
window.toggleCategory = function(categoryId) {
  const section = document.getElementById(`${categoryId}-section`);
  section.classList.toggle('expanded');
};

// Utilities
function showLoading() {
  scanStatus.style.display = 'block';
  resultsContainer.style.display = 'none';
}

function showError(message) {
  scanStatus.innerHTML = `<div style="color: #E74C3C;">❌ ${message}</div>`;
  resultsContainer.style.display = 'none';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

console.log('✅ Popup script initialized');