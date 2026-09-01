const BACKEND_URL = "http://127.0.0.1:5001";

// Auto-inject content script and CSS into existing Gmail tabs on install/startup
function injectIntoGmailTabs() {
    chrome.tabs.query({ url: "*://mail.google.com/*" }, (tabs) => {
        if (!tabs) return;
        for (const tab of tabs) {
            if (tab.id) {
                chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ["contentScript.js"]
                }).catch(() => {});

                chrome.scripting.insertCSS({
                    target: { tabId: tab.id },
                    files: ["contentScript.css"]
                }).catch(() => {});
            }
        }
    });
}

chrome.runtime.onInstalled.addListener(() => {
    console.log("[InnoveXShield] Extension installed/updated. Injecting into Gmail tabs...");
    injectIntoGmailTabs();
});

chrome.runtime.onStartup.addListener(() => {
    injectIntoGmailTabs();
});

// Message listener: API Proxy for background network requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "ANALYZE_EMAIL") {
        fetch(`${BACKEND_URL}/api/analyze-email`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request.payload || {})
        })
        .then(res => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        })
        .then(data => sendResponse({ success: true, data: data }))
        .catch(err => sendResponse({ success: false, error: err.message }));
        return true; // Keep message channel open for async response
    }

    if (request.type === "ANALYZE_URL") {
        fetch(`${BACKEND_URL}/api/analyze-url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, anchorText: request.anchorText || "" })
        })
        .then(res => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        })
        .then(data => sendResponse({ success: true, data: data }))
        .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
    }

    if (request.type === "CHECK_STATUS") {
        fetch(`${BACKEND_URL}/predict`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: "https://google.com" })
        })
        .then(res => sendResponse({ online: res.ok }))
        .catch(() => sendResponse({ online: false }));
        return true;
    }
});
