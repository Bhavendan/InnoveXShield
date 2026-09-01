# InnoveXShield — AI-Powered Phishing Detection & Investigation Platform

An AI-powered browser extension that automatically detects and analyzes potentially malicious links and phishing indicators in emails, helping users identify threats before they interact with them.

## 🚨 Problem Statement

Phishing attacks are one of the most common cybersecurity threats faced by individuals and organizations.

Attackers use:

* Fake login pages
* Malicious URLs
* Typosquatted domains
* Impersonated organizations
* Urgent security alerts
* Credential-harvesting links
* Social engineering
* Suspicious redirects

to trick users into revealing sensitive information.

Traditional phishing detection often requires users to manually inspect URLs, sender addresses, and email content. This creates a significant usability problem because users may not recognize sophisticated phishing attempts.

**InnoveXShield** addresses this problem by automatically analyzing an opened email and its actionable links using machine-learning-based URL analysis and security heuristics.

---

# 💡 Our Solution

InnoveXShield is a Chrome browser extension designed to automatically inspect emails when the user opens them.

The system extracts relevant email information and analyzes the URLs contained within the email.

### Detection Pipeline

```text
Gmail
   │
   ▼
Opened Email Detection
   │
   ▼
Email Content Extraction
   │
   ├── Sender
   ├── Subject
   ├── Email Body
   └── Actionable URLs
          │
          ▼
     URL Analysis
          │
          ├── Domain Analysis
          ├── URL Structure
          ├── HTTPS Analysis
          └── Security Indicators
          │
          ▼
  30 URL Features
          │
          ▼
Gradient Boosting Model
          │
          ▼
URL-Level Prediction
          │
          ▼
Email Security Analysis
          │
          ▼
Risk Scoring Engine
          │
          ▼
┌─────────────────────────┐
│ LEGITIMATE              │
│ SUSPICIOUS              │
│ PHISHING                │
└─────────────────────────┘
```

---

# 🧠 Machine Learning Model

The core URL detection component uses a **Gradient Boosting Classifier** trained on a phishing website dataset.

The model analyzes characteristics of URLs and websites rather than relying only on keywords or email content.

### Dataset

The model was trained using the **Phishing Website Detector dataset**.

The training process includes:

1. Data loading
2. Data preprocessing
3. Exploratory Data Analysis
4. Feature analysis
5. Model training
6. Model comparison
7. Model evaluation
8. Model serialization

### Models Evaluated

Several machine-learning algorithms were evaluated:

* Logistic Regression
* K-Nearest Neighbors
* Support Vector Classifier
* Naive Bayes
* Decision Tree
* Random Forest
* Gradient Boosting
* CatBoost
* Multilayer Perceptron

Gradient Boosting was selected as the primary URL classification model based on its balance between prediction performance and response latency.

---

# 🔍 URL Features

The trained model uses 30 phishing-related URL/website features:

```text
UsingIP
LongURL
ShortURL
Symbol@
Redirecting//
PrefixSuffix-
SubDomains
HTTPS
DomainRegLen
Favicon
NonStdPort
HTTPSDomainURL
RequestURL
AnchorURL
LinksInScriptTags
ServerFormHandler
InfoEmail
AbnormalURL
WebsiteForwarding
StatusBarCust
DisableRightClick
UsingPopupWindow
IframeRedirection
AgeofDomain
DNSRecording
WebsiteTraffic
PageRank
GoogleIndex
LinksPointingToPage
StatsReport
```

The trained model is stored as:

```text
model.pkl
```

---

# 📧 Gmail Email Analysis

Unlike a simple URL checker, InnoveXShield analyzes the context in which URLs appear inside an email.

When a user opens an email, the extension extracts:

```text
Sender
Subject
Email body
Actionable hyperlinks
```

The extension then analyzes the actual hyperlink destination rather than relying only on the visible text.

### Example

```text
Visible text:
Check Activity

Actual destination:
https://accounts.google.com/...
```

The actual destination is analyzed.

The system does **not** automatically classify a URL as phishing merely because the visible anchor text differs from the destination.

---

# 🔗 Intelligent URL Extraction

The extension differentiates between user-clickable links and email resources.

### Actionable URLs

These are analyzed by the phishing detection pipeline.

```text
<a href="https://example.com">
```

### Non-actionable resources

These are not treated as phishing links simply because they contain URLs.

Examples:

```text
<img src="https://...">
```

```text
Email rendering resources
Tracking pixels
Embedded images
CDN resources
CSS resources
```

This helps reduce false positives from legitimate email infrastructure.

---

# 🌐 Domain & Brand Analysis

InnoveXShield performs domain-level analysis to identify suspicious infrastructure.

The system considers:

* Domain structure
* Subdomains
* Typosquatting
* Suspicious domain patterns
* Unauthorized brand impersonation
* Domain reputation
* HTTPS usage
* IP-based URLs
* URL redirection

The system does **not** classify a domain as malicious simply because its hostname contains a brand name.

For example, legitimate infrastructure such as:

```text
accounts.google.com
myaccount.google.com
ci3.googleusercontent.com
lh3.googleusercontent.com
```

must not automatically be treated as phishing.

---

# 🛡️ Risk Assessment

InnoveXShield combines multiple security signals to produce a final risk assessment.

```text
URL ML Prediction
        +
Domain Analysis
        +
Email Analysis
        +
Security Indicators
        ↓
Risk Engine
        ↓
Final Risk Score
```

The system produces three primary classifications:

### 🟢 LEGITIMATE

No significant phishing indicators detected.

### 🟡 SUSPICIOUS

One or more indicators require additional verification.

### 🔴 PHISHING

Strong evidence indicates that the email or an actionable URL may be malicious.

---

# 📊 Detection Output

The extension provides an explainable result rather than simply displaying:

```text
PHISHING
```

It provides information such as:

```text
Classification: PHISHING

Risk Score: 92/100

ML Prediction: PHISHING
ML Probability: 94%

URLs Analyzed: 2
Suspicious URLs: 1

Threat Indicators:
• Suspicious domain
• Malicious URL characteristics
• Credential-harvesting indicator

Recommendation:
Do not click the link or provide credentials.
```

This allows users to understand **why** a message was classified as risky.

---

# 🧩 Browser Extension Architecture

The Chrome extension consists of multiple components.

### `manifest.json`

Defines the extension configuration, permissions, scripts, and browser integration.

### Content Script

Responsible for interacting with the Gmail page and detecting opened emails.

It extracts:

* Sender
* Subject
* Body
* Actionable links

and communicates with the backend.

### Background Service Worker

Handles extension-level operations and communication between components.

### Popup

Provides the user-facing security dashboard.

It displays:

* Email classification
* Risk score
* ML result
* Detected URLs
* Threat indicators
* Security recommendation

---

# ⚙️ Backend & Model Integration

The trained machine-learning model is serialized and exposed through the backend.

The architecture follows:

```text
Chrome Extension
       │
       ▼
Backend API
       │
       ▼
URL Feature Extraction
       │
       ▼
model.pkl
       │
       ▼
Gradient Boosting Classifier
       │
       ▼
Prediction
       │
       ▼
Extension
```

The backend is responsible for:

* Receiving URL analysis requests
* Preparing model input
* Loading the trained model
* Generating predictions
* Returning structured results

---

# 🔄 Automatic Detection

One of the major features of InnoveXShield is automatic scanning.

The intended workflow is:

```text
User opens Gmail
       ↓
Extension detects opened email
       ↓
Email information extracted
       ↓
Actionable URLs extracted
       ↓
URLs analyzed
       ↓
ML model prediction
       ↓
Risk calculation
       ↓
Security result displayed
```

The user should not need to manually copy and paste URLs for normal Gmail analysis.

---

# 🧪 Example

### Legitimate Email

```text
Sender:
no-reply@accounts.google.com

Subject:
Security alert

URL:
https://accounts.google.com/...

Result:

🟢 LEGITIMATE

Risk: LOW

Reason:
The sender and actionable destination use trusted Google infrastructure.
```

### Phishing Email

```text
Sender:
security@paypa1-login.com

Subject:
Your account will be suspended!

URL:
http://paypa1-login.com/verify

Result:

🔴 PHISHING

Risk: HIGH

Indicators:
• Suspicious domain
• Typosquatting
• Insecure HTTP
• Phishing URL characteristics
```

---

# 🏗️ Technology Stack

| Component             | Technology                      |
| --------------------- | ------------------------------- |
| Browser Extension     | Chrome Extension                |
| Frontend              | HTML, CSS, JavaScript           |
| Content Integration   | JavaScript Content Scripts      |
| Background Processing | Chrome Extension Service Worker |
| Machine Learning      | Python                          |
| ML Algorithm          | Gradient Boosting Classifier    |
| Model Serialization   | Pickle                          |
| Backend API           | Spring Boot                     |
| Database              | MySQL                           |
| Communication         | REST API                        |
| Email Platform        | Gmail                           |

---

# 📁 Project Structure

```text
InnoveXShield/
│
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── contentScript.js
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
│
├── model/
│   └── model.pkl
│
├── backend/
│   └── ...
│
├── training/
│   └── phishing-attack-detection.ipynb
│
├── README.md
└── ...
```

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
```

## 2. Open Chrome Extensions

Navigate to:

```text
chrome://extensions/
```

## 3. Enable Developer Mode

Enable **Developer mode** in the top-right corner.

## 4. Load the extension

Select:

```text
Load unpacked
```

and choose the project's:

```text
extension/
```

directory.

## 5. Start the backend

Start the Spring Boot backend according to the project's backend configuration.

## 6. Open Gmail

Open Gmail and open an email.

InnoveXShield should automatically analyze the email and display the security result.

---

# 🔐 Security Philosophy

InnoveXShield follows a **defense-in-depth approach**.

Instead of relying on a single signal, the system considers multiple independent indicators.

```text
           ┌───────────────┐
           │ Sender Domain │
           └───────┬───────┘
                   │
┌──────────────┐   │   ┌──────────────┐
│ URL Features │───┼───│ Domain Check │
└──────────────┘   │   └──────────────┘
                   │
           ┌───────▼───────┐
           │  Risk Engine  │
           └───────┬───────┘
                   │
           ┌───────▼───────┐
           │ Final Verdict │
           └───────────────┘
```

The goal is not simply to detect suspicious URLs, but to provide users with an **explainable phishing investigation experience**.

---

# 🎯 Key Features

* 🤖 Machine-learning-based phishing URL detection
* 📧 Automatic Gmail email scanning
* 🔗 Automatic actionable-link extraction
* 🌐 Domain and URL analysis
* 🧠 Gradient Boosting classification
* 🛡️ Brand impersonation detection
* 🔍 Explainable threat indicators
* 📊 Risk scoring
* 🚨 Security recommendations
* ⚡ Automatic detection when an email is opened
* 🖥️ Browser-extension based deployment
* 🔎 Separation of actionable links and email resources
* 🧩 Multi-signal phishing analysis

---

# ⚠️ Limitations

The Gradient Boosting model is trained primarily for **URL/website phishing detection**. It should therefore be treated as one component of the overall email-security pipeline rather than as an email-language classifier.

The final assessment combines ML-based URL analysis with additional email and domain security signals.

No automated phishing detector can guarantee 100% accuracy, so users should still exercise caution when handling sensitive communications.

---

# 👥 Team — InnoveX


Example:

```text
1. DAVIDRAJ K 
2. BHAVENDAN G
3. AFIK ESMAL A 
4. GOKUL KRISHNA C P 
5. DHANASURIYA M G
6. PRITHVI RAJ B
```

---

# 📜 License

This project is released under the **MIT License**.

---

## 🛡️ InnoveXShield

**Detect. Analyze. Protect.**

An intelligent browser-based phishing detection and investigation platform designed to help users identify suspicious emails and malicious links before they become a security incident.
