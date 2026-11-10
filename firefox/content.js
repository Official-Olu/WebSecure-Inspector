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
// DETECTION MODULE 4: CONTENT SECURITY POLICY (CSP)
// ============================================================================

// A content script cannot see the response headers of the page it runs in.
// To read the CSP header the page is requested again from the same origin,
// asking for the headers only. A CSP set in a <meta> tag is read from the page.
async function fetchCSPHeaders() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1500);
  const options = { cache: 'no-store', credentials: 'same-origin', signal: controller.signal };

  try {
    let response = await fetch(window.location.href, Object.assign({ method: 'HEAD' }, options));

    // Some servers do not answer HEAD requests
    if (response.status === 405 || response.status === 501) {
      response = await fetch(window.location.href, Object.assign({ method: 'GET' }, options));
    }

    return {
      readable: true,
      enforced: response.headers.get('content-security-policy') || '',
      reportOnly: response.headers.get('content-security-policy-report-only') || ''
    };
  } catch (error) {
    console.log('ℹ️ Could not read response headers:', error.message);
    return { readable: false, enforced: '', reportOnly: '' };
  } finally {
    clearTimeout(timer);
  }
}

// Turns "default-src 'self'; script-src 'self'" into { 'default-src': ["'self'"], ... }
function parseCSP(policyText) {
  const directives = {};

  policyText.split(';').forEach(part => {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return;

    const name = tokens[0].toLowerCase();
    if (!(name in directives)) {
      directives[name] = tokens.slice(1).map(value => value.toLowerCase());
    }
  });

  return directives;
}

// Returns the weaknesses in one policy that affect scripts
function findCSPWeaknesses(directives) {
  const directiveName = 'script-src' in directives ? 'script-src' : 'default-src';
  const sources = directives[directiveName];

  if (!sources) {
    return [{ check: 'no-script-rule', evidence: 'No default-src or script-src directive' }];
  }

  const weaknesses = [];
  const evidence = `${directiveName} ${sources.join(' ')}`;
  const usesNonceOrHash = sources.some(value => /^'(nonce-|sha256-|sha384-|sha512-)/.test(value));
  const usesStrictDynamic = sources.includes("'strict-dynamic'");

  // Browsers ignore 'unsafe-inline' when a nonce or hash is present
  if (sources.includes("'unsafe-inline'") && !usesNonceOrHash) {
    weaknesses.push({ check: 'unsafe-inline', evidence });
  }

  if (sources.includes("'unsafe-eval'")) {
    weaknesses.push({ check: 'unsafe-eval', evidence });
  }

  // Browsers ignore host sources when 'strict-dynamic' is present
  const wildcards = ['*', 'http:', 'https:', 'data:'];
  if (!usesStrictDynamic && sources.some(value => wildcards.includes(value))) {
    weaknesses.push({ check: 'wildcard', evidence });
  }

  return weaknesses;
}

const CSP_MESSAGES = {
  'missing': 'No Content Security Policy found',
  'report-only': 'CSP is in report-only mode and is not enforced',
  'no-script-rule': 'CSP does not restrict where scripts come from',
  'unsafe-inline': "CSP allows inline scripts ('unsafe-inline')",
  'unsafe-eval': "CSP allows eval ('unsafe-eval')",
  'wildcard': 'CSP allows scripts from any site (wildcard source)'
};

function buildCSPIssue(check, evidence) {
  return {
    type: 'CSP Violation',
    severity: 'High',
    check: check,
    evidence: evidence,
    message: CSP_MESSAGES[check],
    points: -10
  };
}

async function detectCSPViolations() {
  console.log('🔍 Checking Content Security Policy...');

  detectionResults.cspViolations = [];
  detectionResults.cspStatus = 'checked';

  // Pages opened from a file have no response headers to check
  if (window.location.protocol !== 'https:' && window.location.protocol !== 'http:') {
    console.log('ℹ️ Page is not served over HTTP or HTTPS - skipping CSP check');
    detectionResults.cspStatus = 'skipped';
    return;
  }

  const headers = await fetchCSPHeaders();

  // A response can carry more than one policy, separated by commas
  const policies = headers.enforced.split(',').map(text => text.trim()).filter(Boolean);

  document.querySelectorAll('meta[http-equiv]').forEach(meta => {
    const name = (meta.getAttribute('http-equiv') || '').toLowerCase();
    const content = (meta.getAttribute('content') || '').trim();
    if (name === 'content-security-policy' && content) {
      policies.push(content);
    }
  });

  const cspIssues = [];

  if (policies.length === 0) {
    if (!headers.readable) {
      // The header could not be read, so a missing policy cannot be confirmed
      detectionResults.cspStatus = 'unreadable';
    } else if (headers.reportOnly) {
      cspIssues.push(buildCSPIssue('report-only', headers.reportOnly));
    } else {
      cspIssues.push(buildCSPIssue('missing', 'No CSP header and no CSP meta tag'));
    }
  } else {
    // The browser enforces every policy together, so a weakness only counts
    // when no policy on the page closes it
    const perPolicy = policies.map(text => findCSPWeaknesses(parseCSP(text)));

    Object.keys(CSP_MESSAGES).forEach(check => {
      const matches = perPolicy.map(list => list.find(item => item.check === check));
      if (matches.every(Boolean)) {
        cspIssues.push(buildCSPIssue(check, matches[0].evidence));
      }
    });
  }

  detectionResults.cspViolations = cspIssues;
  console.log(`✅ CSP: ${cspIssues.length} issues found`);
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

async function runSecurityScan() {
  console.log('🚀 Starting security scan...');
  
  const startTime = performance.now();
  
  detectMixedContent();
  detectUnsafeLinks();
  detectInsecureStorage();
  await detectCSPViolations();
  
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