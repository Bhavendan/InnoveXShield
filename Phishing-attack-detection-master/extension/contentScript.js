(() => {
    // Unwraps Google redirect URLs (e.g. google.com/url?q=https://...)
    function unwrapUrl(rawHref) {
        if (!rawHref) return "";
        let url = rawHref.trim();
        if (url.includes("google.com/url?q=")) {
            try {
                const parsed = new URL(url);
                const actual = parsed.searchParams.get("q");
                if (actual) url = actual;
            } catch (e) {}
        }
        return url;
    }

    // Inspects Gmail DOM and extracts currently open email
    function extractCurrentEmail() {
        console.log("[Phishing Extension] Content Script: Extracting current email from DOM...");

        // 1. Locate Subject Header
        const subjectSelectors = [
            'h2.hP',
            'div[role="main"] h2.hP',
            'h2[data-thread-perm-id]',
            'div[role="main"] h2'
        ];

        let subject = "";
        for (const selector of subjectSelectors) {
            const el = document.querySelector(selector);
            if (el && el.innerText) {
                const text = el.innerText.trim();
                // Avoid capturing Gmail search bar placeholder or nav headings
                if (text && text !== "Search mail" && text !== "Search in mail" && text !== "Gmail") {
                    subject = text;
                    break;
                }
            }
        }

        // 2. Locate Active Message Container in Thread
        const messageContainers = Array.from(document.querySelectorAll('.adn.ads, .h7, .kv, [data-message-id]'));
        let activeMessageEl = null;

        if (messageContainers.length > 0) {
            // Find the last visible/expanded message
            for (let i = messageContainers.length - 1; i >= 0; i--) {
                const container = messageContainers[i];
                const body = container.querySelector('.a3s, .ii.gt');
                if (body && container.offsetParent !== null && body.innerText.trim().length > 0) {
                    activeMessageEl = container;
                    break;
                }
            }
            if (!activeMessageEl) {
                activeMessageEl = messageContainers[messageContainers.length - 1];
            }
        }

        // Fallback to primary message body if container list is not found
        if (!activeMessageEl) {
            const bodyCandidate = document.querySelector('.a3s, .ii.gt');
            if (bodyCandidate && bodyCandidate.offsetParent !== null) {
                activeMessageEl = bodyCandidate.closest('.adn.ads') || bodyCandidate.parentElement;
            }
        }

        if (!activeMessageEl) {
            console.log("[Phishing Extension] Content Script: No active message container found.");
            return {
                success: false,
                error: "NO_EMAIL_OPEN",
                message: "Please open an email to analyze it."
            };
        }

        // 3. Extract Sender Information
        let senderEmail = "";
        let senderName = "";
        let sender = "";

        const senderSpan = activeMessageEl.querySelector('span.gD, span[email], .gE span[email], .go, .zF, h3 span');
        if (senderSpan) {
            senderEmail = senderSpan.getAttribute('email') || "";
            senderName = senderSpan.getAttribute('name') || "";
            const inner = senderSpan.innerText ? senderSpan.innerText.trim() : "";

            if (!senderEmail && inner.includes("@")) {
                senderEmail = inner;
            }
            if (!senderName && inner && inner !== senderEmail) {
                senderName = inner;
            }

            if (senderName && senderEmail && senderName !== senderEmail) {
                sender = `"${senderName}" <${senderEmail}>`;
            } else {
                sender = senderEmail || senderName || inner;
            }
        }

        // 4. Extract Recipient and Date
        const recipientEl = activeMessageEl.querySelector('span.g2, .hb span, span[data-hovercard-id]');
        const recipient = recipientEl ? (recipientEl.getAttribute('email') || recipientEl.innerText.trim()) : "";

        const dateEl = activeMessageEl.querySelector('.g3, .gH span, .mI');
        const date = dateEl ? (dateEl.getAttribute('title') || dateEl.innerText.trim()) : "";

        // 5. Extract Message Body (HTML and Plain Text)
        const bodyEl = activeMessageEl.querySelector('.a3s, .ii.gt') || activeMessageEl;
        const bodyHtml = bodyEl.innerHTML || "";
        const bodyText = bodyEl.innerText || "";

        // If content is empty or only navigation text, consider no email open
        if (!bodyText.trim() && !subject && (!senderEmail && !senderName)) {
            console.log("[Phishing Extension] Content Script: Email content is empty.");
            return {
                success: false,
                error: "NO_EMAIL_OPEN",
                message: "Please open an email to analyze it."
            };
        }

        // 6. Extract Embedded Hyperlinks & Plain Text URLs
        const linksList = [];
        const seenUrls = new Set();

        // Helper to check if URL is Gmail app shell navigation
        function isGmailInterfaceUrl(href) {
            return href.includes("mail.google.com/mail/u/") || 
                   href.includes("mail.google.com/sync") || 
                   href.includes("accounts.google.com/ServiceLogin");
        }

        // 6a. HTML <a> tags with destination href and visible anchor text
        bodyEl.querySelectorAll('a[href]').forEach(a => {
            let href = unwrapUrl(a.href);
            let anchorText = (a.innerText || a.textContent || "").trim();

            if (href.startsWith("http://") || href.startsWith("https://")) {
                if (!isGmailInterfaceUrl(href)) {
                    if (!seenUrls.has(href)) {
                        seenUrls.add(href);
                        linksList.push({
                            url: href,
                            anchorText: anchorText || href,
                            elementType: 'a',
                            urlType: 'ACTIONABLE'
                        });
                    }
                }
            }
        });

        // 6b. Embedded Image and Resource URLs (for auditing without false phishing flags)
        bodyEl.querySelectorAll('img[src]').forEach(img => {
            let src = unwrapUrl(img.src);
            if (src.startsWith("http://") || src.startsWith("https://")) {
                if (!seenUrls.has(src)) {
                    seenUrls.add(src);
                    linksList.push({
                        url: src,
                        anchorText: '',
                        elementType: 'img',
                        urlType: 'IMAGE_RESOURCE'
                    });
                }
            }
        });

        // 6c. Plain text URLs
        const urlRegex = /https?:\/\/[^\s<>"')]+|www\.[^\s<>"')]+/g;
        const plainMatches = bodyText.match(urlRegex) || [];
        plainMatches.forEach(rawMatch => {
            let href = unwrapUrl(rawMatch);
            if (href.startsWith("www.")) href = "http://" + href;
            href = href.replace(/[.,;)>\]]+$/, "");

            if (href.startsWith("http://") || href.startsWith("https://")) {
                if (!isGmailInterfaceUrl(href)) {
                    if (!seenUrls.has(href)) {
                        seenUrls.add(href);
                        linksList.push({
                            url: href,
                            anchorText: href,
                            elementType: 'plain_text',
                            urlType: 'ACTIONABLE'
                        });
                    }
                }
            }
        });

        console.log(`[Phishing Extension] Content Script: Extracted ${linksList.length} links/resources from email.`);

        return {
            success: true,
            email: {
                sender: sender,
                senderEmail: senderEmail,
                senderName: senderName,
                recipient: recipient,
                date: date,
                subject: subject,
                body: bodyText,
                html: bodyHtml,
                links: linksList
            }
        };
    }

    // Single message listener: responds on-demand when popup requests GET_CURRENT_EMAIL
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.type === "GET_CURRENT_EMAIL" || request.type === "EXTRACT_EMAIL") {
            try {
                const result = extractCurrentEmail();
                sendResponse(result);
            } catch (err) {
                console.error("[Phishing Extension] Content Script extraction error:", err);
                sendResponse({
                    success: false,
                    error: "EXTRACTION_ERROR",
                    message: "Error extracting email content."
                });
            }
            return true;
        }
    });

    console.log("[Phishing Extension] Content script initialized and ready for on-demand inspection.");
})();
