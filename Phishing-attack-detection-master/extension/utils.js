export const getActiveTabURL = async () => {
    try {
        let [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (tab && tab.url && !tab.url.startsWith("chrome-extension://")) {
            return tab;
        }
    } catch (e) {}

    try {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url && !tab.url.startsWith("chrome-extension://")) {
            return tab;
        }
    } catch (e) {}

    let tabs = await chrome.tabs.query({ active: true });
    for (const t of (tabs || [])) {
        if (t.url && !t.url.startsWith("chrome-extension://")) {
            return t;
        }
    }
    return tabs && tabs.length > 0 ? tabs[0] : null;
};