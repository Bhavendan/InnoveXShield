import { getActiveTabURL } from "./utils.js";
import { downloadReport } from "./reportGenerator.js";

let currentAnalysisResult = null;
let currentEmailData = null;
let manualAnalysisResult = null;
let manualEmailData = null;

function checkBackendStatus() {
    const badge = document.getElementById("serverStatus");
    if (!badge) return;
    chrome.runtime.sendMessage({ type: "CHECK_STATUS" }, (response) => {
        if (response && response.online) {
            badge.textContent = "🟢 Online (5001)";
            badge.className = "server-badge online";
        } else {
            badge.textContent = "🔴 Offline";
            badge.className = "server-badge offline";
        }
    });
}

function showState(stateName, customMessage = "") {
    const loadingState = document.getElementById("loadingState");
    const notMailState = document.getElementById("notMailState");
    const emailResultView = document.getElementById("emailResultView");

    loadingState.style.display = "none";
    notMailState.style.display = "none";
    emailResultView.style.display = "none";

    if (stateName === "LOADING") {
        loadingState.style.display = "flex";
        const loadingText = loadingState.querySelector(".loading-text");
        if (loadingText) loadingText.textContent = customMessage || "🔍 Analyzing current email...";
    } else if (stateName === "EMPTY") {
        notMailState.style.display = "block";
        const titleEl = notMailState.querySelector(".state-title");
        const descEl = notMailState.querySelector(".state-desc");
        if (titleEl) titleEl.textContent = "📩 Please open an email first";
        if (descEl) descEl.textContent = customMessage || "Open an individual email in Gmail and click this extension to analyze it.";
    } else if (stateName === "ERROR") {
        notMailState.style.display = "block";
        const titleEl = notMailState.querySelector(".state-title");
        const descEl = notMailState.querySelector(".state-desc");
        if (titleEl) titleEl.textContent = "⚠️ Notice";
        if (descEl) descEl.textContent = customMessage || "Unable to extract email content. Please refresh the page.";
    } else if (stateName === "RESULT") {
        emailResultView.style.display = "block";
    }
}

function renderLinksList(links) {
    const container = document.getElementById("linksContainer");
    const countBadge = document.getElementById("linkCountBadge");
    container.innerHTML = "";
    countBadge.textContent = (links || []).length;

    if (!links || links.length === 0) {
        container.innerHTML = '<div class="state-desc" style="padding: 10px 0; text-align: center;">No external links detected in this email.</div>';
        return;
    }

    links.forEach(item => {
        const linkCard = document.createElement("div");
        const isResource = item.urlType && item.urlType !== "ACTIONABLE";
        const verdictClass = isResource ? "safe" : (item.verdict || "SAFE").toLowerCase();
        linkCard.className = `link-item ${verdictClass}`;

        const isHttps = item.https ? "HTTPS" : "HTTP (Insecure)";
        const typeBadge = isResource ? `<span class="mini-badge" style="background:#f1f5f9;color:#64748b;font-size:9px;margin-right:4px;">${item.urlType}</span>` : '';

        let reasonsHtml = "";
        if (item.reasons && item.reasons.length > 0) {
            reasonsHtml = `<ul class="link-reasons">${item.reasons.map(r => `<li>${r}</li>`).join("")}</ul>`;
        }

        linkCard.innerHTML = `
            <div class="link-header-row">
                <span class="link-anchor-title" title="${item.anchorText || item.originalUrl}">${typeBadge}${item.anchorText || item.originalUrl}</span>
                <span class="link-score-badge ${verdictClass}">
                    ${isResource ? 'RESOURCE' : item.verdict + ' (' + item.riskScore + '/100)'}
                </span>
            </div>
            <div class="link-url-text">${item.originalUrl}</div>
            <div class="link-meta-tags">
                <span>🌐 ${item.domain}</span>
                <span>🔒 ${isHttps}</span>
                ${isResource ? '<span style="color:#64748b;">(Excluded from URL risk)</span>' : ''}
            </div>
            ${reasonsHtml}
        `;
        container.appendChild(linkCard);
    });
}

function renderInvestigationResult(data, emailPayload) {
    currentAnalysisResult = data;
    currentEmailData = emailPayload;
    showState("RESULT");

    const classification = (data.classification || data.emailVerdict || "LEGITIMATE").toUpperCase();
    const riskScore = data.risk_score !== undefined ? data.risk_score : (data.overallRiskScore || 0);
    const confidence = data.confidence || 90;
    const mlPrediction = (data.ml_prediction || "LEGITIMATE").toUpperCase();
    const mlProb = data.ml_probability !== undefined ? data.ml_probability : 0.0;

    // 1. Verdict Banner
    const verdictBanner = document.getElementById("verdictBanner");
    const verdictText = document.getElementById("verdictText");
    const verdictMeta = document.getElementById("verdictMeta");
    const verdictIcon = document.getElementById("verdictIcon");
    const riskScorePill = document.getElementById("riskScorePill");

    const verdictLower = classification === "PHISHING" ? "phishing" : (classification === "SUSPICIOUS" ? "suspicious" : "legitimate");
    verdictBanner.className = `verdict-banner ${verdictLower}`;
    
    if (classification === "PHISHING") {
        verdictText.textContent = "PHISHING DETECTED";
        verdictIcon.textContent = "🔴";
    } else if (classification === "SUSPICIOUS") {
        verdictText.textContent = "SUSPICIOUS EMAIL";
        verdictIcon.textContent = "🟡";
    } else {
        verdictText.textContent = "EMAIL APPEARS LEGITIMATE";
        verdictIcon.textContent = "🟢";
    }

    verdictMeta.textContent = `Confidence: ${confidence}% • Risk Level: ${data.riskLevel || (classification === 'PHISHING' ? 'HIGH' : (classification === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW'))}`;
    riskScorePill.textContent = `${riskScore}/100`;

    // 2. ML Model & Summary Card
    const mlVerdictBadge = document.getElementById("mlVerdictBadge");
    const actionableUrlsCount = document.getElementById("actionableUrlsCount");
    const resourceUrlsCount = document.getElementById("resourceUrlsCount");
    const suspiciousUrlsCount = document.getElementById("suspiciousUrlsCount");
    const mlProbText = document.getElementById("mlProbText");

    const actionable = data.actionable_urls !== undefined ? data.actionable_urls : (data.urls_analyzed || 0);
    const resources = data.resource_urls_ignored !== undefined ? data.resource_urls_ignored : 0;
    const suspiciousUrls = data.suspicious_urls !== undefined ? data.suspicious_urls : (data.detectedLinks ? data.detectedLinks.filter(l => l.verdict !== 'SAFE' && l.urlType === 'ACTIONABLE').length : 0);

    if (actionableUrlsCount) actionableUrlsCount.textContent = actionable;
    if (resourceUrlsCount) resourceUrlsCount.textContent = resources;
    if (suspiciousUrlsCount) suspiciousUrlsCount.textContent = suspiciousUrls;
    if (mlProbText) mlProbText.textContent = `${Math.round(mlProb * 100)}%`;

    if (mlVerdictBadge) {
        if (mlPrediction === "PHISHING") {
            mlVerdictBadge.className = "mini-badge threat";
            mlVerdictBadge.textContent = `ML: PHISHING (${Math.round(mlProb * 100)}%)`;
        } else {
            mlVerdictBadge.className = "mini-badge safe";
            mlVerdictBadge.textContent = `ML: LEGITIMATE (${Math.round((1 - mlProb) * 100)}%)`;
        }
    }

    // 3. Sender Card
    const sender = data.senderAnalysis || {};
    document.getElementById("senderEmailText").textContent = data.sender || sender.email || sender.displayName || (emailPayload ? emailPayload.sender : "Unknown Sender");
    document.getElementById("subjectText").textContent = data.subject || ((emailPayload && emailPayload.subject) ? emailPayload.subject : "(No Subject)");

    const senderStatusBadge = document.getElementById("senderStatusBadge");
    const senderAlerts = document.getElementById("senderAlerts");

    if (sender.suspicious) {
        senderStatusBadge.className = "mini-badge threat";
        senderStatusBadge.textContent = "Suspicious Sender";
        senderAlerts.style.display = "block";
        senderAlerts.textContent = sender.reasons ? sender.reasons.join(". ") : "Sender address may be impersonating a trusted brand.";
    } else {
        senderStatusBadge.className = "mini-badge safe";
        senderStatusBadge.textContent = "Verified Domain";
        senderAlerts.style.display = "none";
    }

    // 4. Links Section
    renderLinksList(data.detectedLinks || []);

    // 5. Why? Threat Indicators Card
    const indicatorsCard = document.getElementById("indicatorsCard");
    const indicatorsList = document.getElementById("indicatorsList");
    if (data.indicators && data.indicators.length > 0) {
        indicatorsCard.style.display = "block";
        indicatorsList.innerHTML = data.indicators.map(ind => {
            if (typeof ind === 'object' && ind.message) {
                const sevBadge = ind.severity ? `[${ind.severity}] ` : '';
                return `<li><strong>${sevBadge}</strong>${ind.message}</li>`;
            }
            return `<li>${ind}</li>`;
        }).join("");
    } else {
        indicatorsCard.style.display = "none";
    }

    // 6. Security Recommendation Card
    const recommendationText = document.getElementById("recommendationText");
    const explanationText = document.getElementById("explanationText");

    let recMessage = "No significant phishing indicators detected. Safe to open.";
    if (data.recommended_action === "DO_NOT_CLICK" || classification === "PHISHING") {
        recMessage = "🚨 Recommendation: Do not click links or provide credentials.";
    } else if (data.recommended_action === "PROCEED_WITH_CAUTION" || classification === "SUSPICIOUS") {
        recMessage = "⚠️ Recommendation: Additional verification recommended before interacting with links.";
    }

    if (recommendationText) recommendationText.textContent = recMessage;
    if (explanationText) explanationText.textContent = data.explanation || "";
}

// Communicates with content script on active tab and initiates backend analysis
async function runEmailInvestigation() {
    console.log("[Phishing Extension] Popup opened");
    showState("LOADING", "🔍 Analyzing current email...");

    let activeTab;
    try {
        activeTab = await getActiveTabURL();
    } catch (e) {
        console.error("[Phishing Extension] Failed to query active tab:", e);
    }

    if (!activeTab || !activeTab.id) {
        console.warn("[Phishing Extension] No active tab found.");
        showState("EMPTY", "Please open an email in Gmail to analyze it.");
        return;
    }

    console.log(`[Phishing Extension] Active tab detected: ${activeTab.url || "unknown URL"}`);

    if (!activeTab.url || !activeTab.url.includes("mail.google.com")) {
        console.log("[Phishing Extension] Active tab is not a Gmail page.");
        showState("EMPTY", "Please open an email in Gmail to analyze it.");
        return;
    }

    console.log("[Phishing Extension] Requesting current email from content script...");

    // Helper to send message with auto-injection retry
    const requestEmailFromTab = () => {
        return new Promise((resolve) => {
            chrome.tabs.sendMessage(activeTab.id, { type: "GET_CURRENT_EMAIL" }, (response) => {
                if (chrome.runtime.lastError || !response) {
                    // Try injecting content script dynamically if not yet loaded
                    chrome.scripting.executeScript({
                        target: { tabId: activeTab.id },
                        files: ["contentScript.js"]
                    }, () => {
                        if (chrome.runtime.lastError) {
                            resolve(null);
                            return;
                        }
                        // Retry sending message after injection
                        setTimeout(() => {
                            chrome.tabs.sendMessage(activeTab.id, { type: "GET_CURRENT_EMAIL" }, (retryResponse) => {
                                if (chrome.runtime.lastError || !retryResponse) {
                                    resolve(null);
                                } else {
                                    resolve(retryResponse);
                                }
                            });
                        }, 100);
                    });
                } else {
                    resolve(response);
                }
            });
        });
    };

    const extractionResult = await requestEmailFromTab();

    if (!extractionResult) {
        console.warn("[Phishing Extension] Content script could not be contacted.");
        showState("ERROR", "Unable to access this email page. Please refresh the email page and try again.");
        return;
    }

    if (!extractionResult.success || !extractionResult.email) {
        console.log("[Phishing Extension] No email open on screen.");
        showState("EMPTY", extractionResult.message || "Please open an individual email in Gmail to analyze it.");
        return;
    }

    const emailData = extractionResult.email;
    console.log("[Phishing Extension] Email detected");
    console.log(`[Phishing Extension] Sender: ${emailData.sender || "(none)"}`);
    console.log(`[Phishing Extension] Subject: ${emailData.subject || "(none)"}`);
    console.log(`[Phishing Extension] Links detected: ${emailData.links ? emailData.links.length : 0}`);

    console.log("[Phishing Extension] Sending email for analysis...");

    chrome.runtime.sendMessage({
        type: "ANALYZE_EMAIL",
        payload: emailData
    }, (apiResponse) => {
        if (!apiResponse || !apiResponse.success || !apiResponse.data) {
            console.error("[Phishing Extension] Backend analysis failed:", apiResponse ? apiResponse.error : "No response");
            showState("ERROR", "Unable to connect to the analysis server. Make sure the backend is running on port 5001.");
            return;
        }

        const analysisData = apiResponse.data;
        console.log(`[Phishing Extension] Analysis received: ${analysisData.emailVerdict} (Confidence: ${analysisData.confidence}%, Risk: ${analysisData.overallRiskScore}/100)`);
        console.log(`[Phishing Extension] Verdict: ${analysisData.emailVerdict}`);

        renderInvestigationResult(analysisData, emailData);
    });
}

document.addEventListener("DOMContentLoaded", () => {
    checkBackendStatus();

    // Tab Navigation
    const tabEmailBtn = document.getElementById("tabEmailBtn");
    const tabManualBtn = document.getElementById("tabManualBtn");
    const emailView = document.getElementById("emailView");
    const manualView = document.getElementById("manualView");

    tabEmailBtn.addEventListener("click", () => {
        tabEmailBtn.className = "tab-btn active";
        tabManualBtn.className = "tab-btn";
        emailView.className = "tab-content active";
        manualView.className = "tab-content";
    });

    tabManualBtn.addEventListener("click", () => {
        tabManualBtn.className = "tab-btn active";
        tabEmailBtn.className = "tab-btn";
        manualView.className = "tab-content active";
        emailView.className = "tab-content";
    });

    // Download Report Button (Tab 1)
    const downloadReportBtn = document.getElementById("downloadReportBtn");
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener("click", () => {
            if (currentAnalysisResult) {
                downloadReport(currentAnalysisResult, currentEmailData || {});
            }
        });
    }

    // Re-scan Button
    document.getElementById("rescanBtn")?.addEventListener("click", runEmailInvestigation);

    // Manual URL Scanner
    const manualUrlBtn = document.getElementById("manualUrlBtn");
    const manualUrlInput = document.getElementById("manualUrlInput");
    const manualUrlResult = document.getElementById("manualUrlResult");

    manualUrlBtn.addEventListener("click", () => {
        const url = manualUrlInput.value.trim();
        if (!url) return;

        manualUrlResult.style.display = "block";
        manualUrlResult.className = "manual-output link-badge loading";
        manualUrlResult.textContent = "Scanning URL...";

        chrome.runtime.sendMessage({
            type: "ANALYZE_URL",
            url: url
        }, (response) => {
            if (!response || !response.success || !response.data) {
                manualUrlResult.className = "manual-output link-item malicious";
                manualUrlResult.textContent = "Failed to connect to backend server on port 5001.";
                return;
            }
            const data = response.data;
            const verdict = data.verdict || "SAFE";
            manualUrlResult.className = `manual-output link-item ${verdict.toLowerCase()}`;
            manualUrlResult.innerHTML = `
                <div class="link-header-row">
                    <strong>${verdict} (${data.riskScore}/100 Risk)</strong>
                    <span>🔒 ${data.https ? 'HTTPS' : 'HTTP'}</span>
                </div>
                <div style="margin-top:4px;">Domain: <code>${data.domain}</code></div>
                <ul class="link-reasons" style="margin-top:4px;">${(data.reasons || []).map(r => `<li>${r}</li>`).join("")}</ul>
                <div style="margin-top:8px;">
                    <button id="manualDownloadUrlBtn" class="btn-secondary full-width" style="padding:6px; font-size:11px;">📥 Download URL Report</button>
                </div>
            `;
            document.getElementById("manualDownloadUrlBtn")?.addEventListener("click", () => {
                const reportPayload = {
                    classification: verdict === 'MALICIOUS' ? 'PHISHING' : (verdict === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'LEGITIMATE'),
                    risk_score: data.riskScore,
                    confidence: data.confidence || 95,
                    explanation: (data.reasons || []).join('. '),
                    detectedLinks: [{
                        originalUrl: url,
                        domain: data.domain,
                        protocol: data.https ? 'HTTPS' : 'HTTP',
                        https: data.https,
                        urlType: 'ACTIONABLE',
                        verdict: verdict,
                        riskScore: data.riskScore,
                        reasons: data.reasons
                    }],
                    indicators: data.indicators || []
                };
                downloadReport(reportPayload, { subject: `URL Scan: ${data.domain}`, sender: 'Manual URL Scan' });
            });
        });
    });

    // Manual Email Scanner
    const manualEmailBtn = document.getElementById("manualEmailBtn");
    const manualSenderInput = document.getElementById("manualSenderInput");
    const manualSubjectInput = document.getElementById("manualSubjectInput");
    const manualBodyInput = document.getElementById("manualBodyInput");
    const manualEmailResult = document.getElementById("manualEmailResult");

    manualEmailBtn.addEventListener("click", () => {
        const body = manualBodyInput.value.trim();
        if (!body) return;

        manualEmailResult.style.display = "block";
        manualEmailResult.className = "manual-output link-badge loading";
        manualEmailResult.textContent = "Investigating Email Content...";

        const payload = {
            sender: manualSenderInput.value.trim(),
            subject: manualSubjectInput.value.trim(),
            body: body,
            html: body
        };

        chrome.runtime.sendMessage({
            type: "ANALYZE_EMAIL",
            payload: payload
        }, (response) => {
            if (!response || !response.success || !response.data) {
                manualEmailResult.className = "manual-output link-item malicious";
                manualEmailResult.textContent = "Failed to connect to backend server.";
                return;
            }
            const data = response.data;
            const verdict = data.emailVerdict || "LEGITIMATE";
            manualAnalysisResult = data;
            manualEmailData = payload;

            manualEmailResult.className = `manual-output link-item ${verdict.toLowerCase()}`;
            manualEmailResult.innerHTML = `
                <div class="link-header-row">
                    <strong>Verdict: ${verdict} (${data.confidence}% Confidence • Risk: ${data.riskLevel})</strong>
                </div>
                <p style="margin: 6px 0; font-size: 11px;">${data.explanation}</p>
                <div style="font-weight:700; margin-top:6px;">Detected Links (${(data.detectedLinks || []).length}):</div>
                ${data.detectedLinks && data.detectedLinks.length > 0 ? 
                    data.detectedLinks.map(l => `<div style="margin: 3px 0; font-size: 10.5px;">• <strong>${l.verdict}</strong> [${l.riskScore}/100]: <a href="${l.originalUrl}" target="_blank">${l.domain}</a> (${(l.reasons || []).join(', ')})</div>`).join('')
                    : '<div style="font-size: 10.5px; color:#64748b;">No links detected in this email.</div>'
                }
                <div style="margin-top:8px;">
                    <button id="manualDownloadEmailBtn" class="btn-secondary full-width" style="padding:6px; font-size:11px;">📥 Download Email Report</button>
                </div>
            `;
            document.getElementById("manualDownloadEmailBtn")?.addEventListener("click", () => {
                downloadReport(manualAnalysisResult, manualEmailData);
            });
        });
    });

    // Automatically trigger on-demand scan when extension icon is clicked
    runEmailInvestigation();
});
