/**
 * WebSecure Inspector - Background Service Worker (Firefox)
 * Coordinates between content scripts and popup
 */

console.log('🔧 Background service worker initialized');

// Store scan results by tab ID
const scanResults = new Map();

// ============================================================================
// MESSAGE HANDLERS
// ============================================================================

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('📬 Background received:', message.type);
  
  if (message.type === 'SCAN_RESULTS') {
    handleScanResults(message.results, sender.tab.id);
    sendResponse({ status: 'Results received' });
  }
  
  if (message.type === 'GET_RESULTS') {
    handleGetResults(message.tabId, sendResponse);
    return true;
  }
  
  if (message.type === 'REQUEST_SCAN') {
    handleRequestScan(message.tabId, sendResponse);
    return true;
  }
  
  return false;
});

function handleScanResults(results, tabId) {
  console.log(`📊 Results received for tab ${tabId}`);
  
  scanResults.set(tabId, {
    ...results,
    timestamp: Date.now()
  });
  
  updateBadge(tabId, results.score);
}

async function handleGetResults(tabId, sendResponse) {
  console.log(`📤 Getting results for tab ${tabId}`);
  
  if (scanResults.has(tabId)) {
    sendResponse({ results: scanResults.get(tabId) });
  } else {
    console.log('No results, triggering scan...');
    await requestScanForTab(tabId);
    
    setTimeout(() => {
      if (scanResults.has(tabId)) {
        sendResponse({ results: scanResults.get(tabId) });
      } else {
        sendResponse({ error: 'Scan timeout' });
      }
    }, 2000);
  }
}

async function handleRequestScan(tabId, sendResponse) {
  console.log(`🔄 New scan requested for tab ${tabId}`);
  
  try {
    await requestScanForTab(tabId);
    
    setTimeout(() => {
      if (scanResults.has(tabId)) {
        sendResponse({ status: 'success', results: scanResults.get(tabId) });
      } else {
        sendResponse({ status: 'timeout' });
      }
    }, 2000);
  } catch (error) {
    sendResponse({ status: 'error', message: error.message });
  }
}

async function requestScanForTab(tabId) {
  try {
    await browser.tabs.sendMessage(tabId, { type: 'START_SCAN' });
    console.log(`✅ Scan request sent to tab ${tabId}`);
  } catch (error) {
    console.error(`❌ Error sending scan request:`, error);
    throw error;
  }
}

function updateBadge(tabId, score) {
  let color;
  if (score >= 90) color = '#02C39A';
  else if (score >= 75) color = '#3498DB';
  else if (score >= 60) color = '#F39C12';
  else color = '#E74C3C';
  
  browser.action.setBadgeText({ tabId: tabId, text: score.toString() });
  browser.action.setBadgeBackgroundColor({ tabId: tabId, color: color });
}

// ============================================================================
// TAB MANAGEMENT
// ============================================================================

browser.tabs.onRemoved.addListener((tabId) => {
  if (scanResults.has(tabId)) {
    scanResults.delete(tabId);
    console.log(`🗑️ Cleared results for tab ${tabId}`);
  }
});

browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    if (scanResults.has(tabId)) {
      scanResults.delete(tabId);
    }
    browser.action.setBadgeText({ tabId: tabId, text: '' });
  }
});

browser.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('🎉 WebSecure Inspector installed!');
  }
});

console.log('✅ Background service worker ready');