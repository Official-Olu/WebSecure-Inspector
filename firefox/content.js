/**
 * WebSecure Inspector - Content Script (Firefox)
 * Analyzes web pages for security misconfigurations
 */

console.log('🔍 WebSecure Inspector: Content script loaded');

// Store detection results
const detectionResults = {
  mixedContent: [],
  unsafeLinks: [],
  insecureStorage: [],
  cspViolations: [],
  pageUrl: window.location.href,
  pageProtocol: window.location.protocol,
  scanTimestamp: new Date().toISOString()
};

// ============================================================================
// DETECTION MODULE 1: MIXED CONTENT
// ============================================================================

function detectMixedContent() {
  console.log('🔍 Checking for mixed content...');
  
  if (window.location.protocol !== 'https:') {
    console.log('ℹ️ Page is not HTTPS - skipping mixed content check');
    return;
  }
  
  const mixedContentIssues = [];
  
  // Resource elements to check
  const resourceElements = [
    { tag: 'img', attr: 'src' },
    { tag: 'script', attr: 'src' },
    { tag: 'link', attr: 'href' },
    { tag: 'iframe', attr: 'src' },
    { tag: 'video', attr: 'src' },
    { tag: 'audio', attr: 'src' }
  ];
  
  resourceElements.forEach(({ tag, attr }) => {
    const elements = document.querySelectorAll(tag);
    
    elements.forEach(element => {
      const resourceUrl = element.getAttribute(attr);
      
      if (resourceUrl && resourceUrl.toLowerCase().startsWith('http://')) {
        mixedContentIssues.push({
          type: 'Mixed Content',
          severity: 'High',
          element: tag.toUpperCase(),
          url: resourceUrl,
          message: `HTTP ${tag} loaded on HTTPS page`,
          points: -10
        });
      }
    });
  });
  
  detectionResults.mixedContent = mixedContentIssues;
  console.log(`✅ Mixed Content: ${mixedContentIssues.length} issues found`);
}

// ============================================================================
// DETECTION MODULE 2: UNSAFE HYPERLINKS
// ============================================================================

function detectUnsafeLinks() {
  console.log('🔍 Checking for unsafe hyperlinks...');
  
  const unsafeLinkIssues = [];
  const anchorElements = document.querySelectorAll('a');
  
  anchorElements.forEach(anchor => {
    const target = anchor.getAttribute('target');
    const rel = anchor.getAttribute('rel') || '';
    
    if (target === '_blank') {
      const hasNoopener = rel.includes('noopener');
      const hasNoreferrer = rel.includes('noreferrer');
      
      if (!hasNoopener || !hasNoreferrer) {
        const missing = [];
        if (!hasNoopener) missing.push('noopener');
        if (!hasNoreferrer) missing.push('noreferrer');
        
        unsafeLinkIssues.push({
          type: 'Unsafe Hyperlink',
          severity: 'Medium',
          element: 'A',
          url: anchor.href,
          missing: missing,
          message: `Link missing: ${missing.join(', ')}`,
          points: -5
        });
      }
    }
  });
  
  detectionResults.unsafeLinks = unsafeLinkIssues;
  console.log(`✅ Unsafe Links: ${unsafeLinkIssues.length} issues found`);
}

// ============================================================================
// DETECTION MODULE 3: INSECURE STORAGE
// ============================================================================

function detectInsecureStorage() {
  console.log('🔍 Checking for insecure storage...');
  
  const insecureStorageIssues = [];
  
  // Sensitivity keywords
  const sensitivityKeywords = [
    'password', 'passwd', 'pwd', 'pass',
    'token', 'accesstoken', 'refreshtoken', 'bearer',
    'secret', 'apisecret', 'privatekey',
    'apikey', 'api_key', 'key',
    'ssn', 'socialsecurity',
    'creditcard', 'cardnumber', 'cvv',
    'session', 'sessionid', 'sid'
  ];
  
  // Check localStorage
  if (typeof localStorage !== 'undefined') {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      
      const keyLower = key.toLowerCase();
      const valueLower = value ? value.toLowerCase() : '';
      
      for (const keyword of sensitivityKeywords) {
        if (keyLower.includes(keyword) || valueLower.includes(keyword)) {
          insecureStorageIssues.push({
            type: 'Insecure Storage',
            severity: 'Critical',
            storageType: 'localStorage',
            key: key,
            matchedKeyword: keyword,
            message: `Potential sensitive data in localStorage (matched: "${keyword}")`,
            points: -20
          });
          break;
        }
      }
    }
  }
  
  // Check sessionStorage
  if (typeof sessionStorage !== 'undefined') {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const value = sessionStorage.getItem(key);
      
      const keyLower = key.toLowerCase();
      const valueLower = value ? value.toLowerCase() : '';
      
      for (const keyword of sensitivityKeywords) {
        if (keyLower.includes(keyword) || valueLower.includes(keyword)) {
          insecureStorageIssues.push({
            type: 'Insecure Storage',
            severity: 'Critical',
            storageType: 'sessionStorage',
            key: key,
            matchedKeyword: keyword,
            message: `Potential sensitive data in sessionStorage (matched: "${keyword}")`,
            points: -20
          });
          break;
        }
      }
    }
  }
  
  detectionResults.insecureStorage = insecureStorageIssues;
  console.log(`✅ Insecure Storage: ${insecureStorageIssues.length} issues found`);
}

// ============================================================================
// DETECTION MODULE 4: CSP (Placeholder)
// ============================================================================

function detectCSPViolations() {
  console.log('🔍 CSP detection (placeholder)...');
  detectionResults.cspViolations = [];
}

// ============================================================================
// SCORING
// ============================================================================

function calculateSecurityScore(results) {
  let score = 100;
  
  results.mixedContent.forEach(issue => { score += issue.points; });
  results.unsafeLinks.forEach(issue => { score += issue.points; });
  results.insecureStorage.forEach(issue => { score += issue.points; });
  results.cspViolations.forEach(issue => { score += issue.points; });
  
  score = Math.max(0, score);
  
  let rating;
  if (score >= 90) rating = 'Excellent';
  else if (score >= 75) rating = 'Good';
  else if (score >= 60) rating = 'Fair';
  else rating = 'Poor';
  
  return { score, rating };
}

// ============================================================================
// MAIN SCAN
// ============================================================================

function runSecurityScan() {
  console.log('🚀 Starting security scan...');
  
  const startTime = performance.now();
  
  detectMixedContent();
  detectUnsafeLinks();
  detectInsecureStorage();
  detectCSPViolations();
  
  const scoreData = calculateSecurityScore(detectionResults);
  detectionResults.score = scoreData.score;
  detectionResults.rating = scoreData.rating;
  
  const endTime = performance.now();
  detectionResults.scanDuration = endTime - startTime;
  
  console.log(`✅ Scan complete: ${scoreData.score}/100 (${scoreData.rating})`);
  
  sendResultsToBackground();
}

function sendResultsToBackground() {
  // Firefox browser.* APIs return promises and do not accept callbacks
  browser.runtime.sendMessage({
    type: 'SCAN_RESULTS',
    results: detectionResults
  }).then(() => {
    console.log('✅ Results sent to background');
  }).catch((error) => {
    console.error('Error sending results:', error);
  });
}

// ============================================================================
// LISTENERS
// ============================================================================

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'START_SCAN') {
    console.log('📬 Received scan request');
    runSecurityScan();
    sendResponse({ status: 'Scan started' });
  }
  return true;
});

// Auto-scan on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', runSecurityScan);
} else {
  runSecurityScan();
}

console.log('✅ Content script initialized');