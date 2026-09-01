import re
import html
import socket
import ipaddress
from urllib.parse import urlparse, unquote, parse_qs
from bs4 import BeautifulSoup
import numpy as np

KNOWN_BRANDS = [
    'google', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix',
    'facebook', 'instagram', 'whatsapp', 'yahoo', 'bankofamerica',
    'chase', 'wellsfargo', 'skcet', 'github', 'linkedin', 'twitter',
    'dropbox', 'adobe', 'ebay', 'spotify', 'binance', 'coinbase',
    'nptel', 'iitm'
]

# Centralized allowlist mapping brands to their authorized registrable/root domains
BRAND_AUTHORIZED_DOMAINS = {
    'google': {
        'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.de',
        'google.fr', 'google.com.au', 'google.org', 'google.edu', 'google.net',
        'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'googlemail.com',
        'youtube.com', 'youtu.be', 'gmail.com', 'android.com', 'chrome.com',
        'withgoogle.com', 'googleblog.com', 'appspot.com', 'forms.gle', 'chromewebstore.google.com'
    },
    'microsoft': {
        'microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com',
        'azure.com', 'msn.com', 'bing.com', 'microsoftonline.com', 'visualstudio.com',
        'skype.com', 'sharepoint.com', 'onedrive.com', 'microsoftsupport.com', 'msft.net'
    },
    'apple': {
        'apple.com', 'icloud.com', 'itunes.com', 'me.com', 'apple-dns.net', 'mzstatic.com'
    },
    'amazon': {
        'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.fr',
        'aws.amazon.com', 'amazonaws.com', 'amazonses.com', 'media-amazon.com',
        'ssl-images-amazon.com', 'primevideo.com', 'awstrack.me'
    },
    'paypal': {
        'paypal.com', 'paypal.me', 'paypalobjects.com'
    },
    'netflix': {
        'netflix.com', 'nflxso.net', 'nflxext.com', 'nflximg.net'
    },
    'facebook': {
        'facebook.com', 'fb.com', 'facebookmail.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com', 'meta.com'
    },
    'github': {
        'github.com', 'githubusercontent.com', 'github.io', 'github.community', 'github.blog'
    },
    'linkedin': {
        'linkedin.com', 'licdn.com'
    },
    'nptel': {
        'nptel.ac.in', 'iitm.ac.in', 'swayam.gov.in'
    },
    'iitm': {
        'iitm.ac.in', 'nptel.ac.in'
    },
    'skcet': {
        'skcet.ac.in', 'shikshavertex.in'
    }
}

TRUSTED_EMAIL_SERVICES = [
    'sendgrid.net', 'ct.sendgrid.net',
    'mailchimp.com', 'mandrillapp.com', 'list-manage.com', 'chimpstatic.com',
    'hubspot.net', 'hubspot.com', 'hs-sites.com', 'hubspotlinks.com',
    'awstrack.me', 'amazonses.com',
    'mailgun.org', 'mailgun.net',
    'customeriomail.com', 'iterable.com', 'links.iterable.com',
    'salesforce.com', 'exacttarget.com',
    'google.com', 'forms.gle', 'google.co.in',
    'microsoft.com', 'office.com', 'live.com',
    'zoom.us', 'webex.com', 'teams.microsoft.com',
    'nptel.ac.in', 'iitm.ac.in', 'swayam.gov.in', 'internshala.com',
    'coursera.org', 'edx.org', 'udemy.com'
]

TWO_PART_TLDS = {
    'ac.in', 'edu.in', 'gov.in', 'co.in', 'net.in', 'org.in', 'res.in',
    'co.uk', 'ac.uk', 'gov.uk', 'org.uk',
    'edu.au', 'com.au', 'gov.au',
    'co.jp', 'ne.jp', 'ac.jp',
    'com.sg', 'edu.sg', 'gov.sg',
    'co.nz', 'org.nz', 'govt.nz'
}

TYPOS_MAP = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '@': 'a', 'vv': 'w'}

SHORTENERS_REGEX = (
    r'(://|@|\.)('
    r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl\.com|tinyurl|tr\.im|is\.gd|cli\.gs|'
    r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
    r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
    r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|'
    r'db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|'
    r'u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|'
    r'filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net|'
    r'go\.link|cutt\.ly|rebrand\.ly|t\.ly|rb\.gy|dub\.sh|shorturl\.at|buff\.ly|smarturl\.it|bl\.ink'
    r')(/|$|\?|#)'
)

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'security', 'update', 'signin', 'password',
    'banking', 'wallet', 'suspend', 'urgent', 'confirm', 'billing', 'invoice',
    'validate', 'restore', 'recover', 'auth', 'support-service'
]

URGENCY_PATTERNS = [
    r'account.*(suspend|terminat|deactivat|block|restrict)',
    r'(urgent|immediately|immediate action|within 24 hours|within 48 hours|final warning)',
    r'(unauthorized|suspicious|fraudulent).*(activity|transaction|login|access)',
    r'(verify|confirm|validate).*(identity|account|password|details|pin)',
    r'(reset|change).*(password|credential|passcode)',
    r'(refund|prize|winner|lottery|million|crypto|bitcoin|inheritance)',
    r'(unpaid|overdue|outstanding).*(invoice|payment|bill)'
]

def get_registered_domain(domain):
    if not domain:
        return ""
    domain = domain.lower().strip()
    parts = domain.split('.')
    if len(parts) >= 3:
        two_part_candidate = f"{parts[-2]}.{parts[-1]}"
        if two_part_candidate in TWO_PART_TLDS and len(parts) >= 3:
            return f"{parts[-3]}.{two_part_candidate}"
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain

def is_authorized_for_brand(domain, brand):
    if not domain or not brand:
        return False
    domain = domain.lower()
    reg_dom = get_registered_domain(domain)
    brand_lower = brand.lower()
    
    if brand_lower in BRAND_AUTHORIZED_DOMAINS:
        allowed = BRAND_AUTHORIZED_DOMAINS[brand_lower]
        if domain in allowed or reg_dom in allowed:
            return True
        for a in allowed:
            if domain == a or domain.endswith('.' + a):
                return True
    return False

def is_trusted_service(domain):
    if not domain:
        return False
    domain = domain.lower()
    reg_dom = get_registered_domain(domain)
    for trusted in TRUSTED_EMAIL_SERVICES:
        if domain == trusted or domain.endswith('.' + trusted) or reg_dom == trusted:
            return True
    for brand, domains in BRAND_AUTHORIZED_DOMAINS.items():
        if domain in domains or reg_dom in domains:
            return True
        for d in domains:
            if domain == d or domain.endswith('.' + d):
                return True
    return False

def is_institutional_domain(domain):
    if not domain:
        return False
    domain = domain.lower()
    return any(domain.endswith(tld) for tld in ['.ac.in', '.edu.in', '.edu', '.gov', '.gov.in', '.ac.uk', '.res.in'])

def classify_url_type(url, element_tag="a"):
    if not url:
        return "UNKNOWN"
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower().split(':')[0]
        path = (parsed.path or "").lower()

        # Image extensions
        image_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.bmp', '.tiff')
        if element_tag in ['img', 'image'] or any(path.endswith(ext) for ext in image_extensions):
            return "IMAGE_RESOURCE"

        # Google User Content / Gmail image proxy / Avatars
        if 'googleusercontent.com' in hostname and ('/meips/' in path or '/a/' in path or '/gadgets/proxy' in path):
            return "IMAGE_RESOURCE"
        if 'gstatic.com' in hostname and ('/images/' in path or '/icons/' in path or '/favicon' in path or '/branding/' in path):
            return "IMAGE_RESOURCE"

        # Tracking Pixels
        if any(k in path for k in ['/open.gif', '/pixel.gif', '/wf/open', '/track/open', '/beacon']):
            return "TRACKING_RESOURCE"

        # CSS / Stylesheets
        if element_tag in ['link', 'style'] or path.endswith('.css'):
            return "CSS_RESOURCE"

        # Script resources
        if element_tag in ['script'] or path.endswith('.js'):
            return "EMAIL_RENDERING_RESOURCE"

        # Actionable links
        if element_tag in ['a', 'button', 'actionable', 'plain_text']:
            return "ACTIONABLE"

        return "ACTIONABLE"
    except Exception:
        return "ACTIONABLE"

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def unwrap_redirect_url(url):
    try:
        if 'google.com/url?' in url:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if 'q' in qs and qs['q']:
                return qs['q'][0]
            if 'url' in qs and qs['url']:
                return qs['url'][0]
        if 'safelinks.protection.outlook.com/?' in url:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if 'url' in qs and qs['url']:
                return qs['url'][0]
    except Exception:
        pass
    return url

def clean_url(raw_url):
    if not raw_url:
        return ""
    url = html.unescape(raw_url.strip())
    url = unwrap_redirect_url(url)
    # Remove trailing punctuation often attached from plain text
    url = re.sub(r'[\.,;\)\]>]+$', '', url)
    return url

def extract_urls_from_content(html_or_text):
    if not html_or_text:
        return []
    
    extracted = []
    seen_urls = set()

    # 1. Parse HTML for <a> and <button> tags
    try:
        soup = BeautifulSoup(html_or_text, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = clean_url(a_tag['href'])
            anchor_text = a_tag.get_text(separator=' ', strip=True) or ""
            if href.startswith(('http://', 'https://')):
                parsed = urlparse(href)
                if '.' in parsed.netloc and len(parsed.netloc.split('.')[-1]) >= 2:
                    if href not in seen_urls:
                        seen_urls.add(href)
                        extracted.append({
                            'url': href,
                            'anchorText': anchor_text or href,
                            'elementType': 'a',
                            'urlType': classify_url_type(href, 'a')
                        })
        
        # Also detect image resources from <img> tags to classify them
        for img_tag in soup.find_all('img', src=True):
            src = clean_url(img_tag['src'])
            if src.startswith(('http://', 'https://')):
                if src not in seen_urls:
                    seen_urls.add(src)
                    extracted.append({
                        'url': src,
                        'anchorText': '',
                        'elementType': 'img',
                        'urlType': 'IMAGE_RESOURCE'
                    })
    except Exception:
        pass

    # 2. Extract plain-text URLs using Regex
    plain_text = html.unescape(html_or_text)
    url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\')]*|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\')]*')
    matches = url_pattern.findall(plain_text)

    for match in matches:
        href = clean_url(match)
        if href.startswith('www.'):
            href = 'http://' + href
        if href.startswith(('http://', 'https://')) and href not in seen_urls:
            parsed = urlparse(href)
            if '.' in parsed.netloc and len(parsed.netloc.split('.')[-1]) >= 2:
                seen_urls.add(href)
                extracted.append({
                    'url': href,
                    'anchorText': href,
                    'elementType': 'plain_text',
                    'urlType': classify_url_type(href, 'plain_text')
                })

    return extracted

def analyze_single_url(raw_url, anchor_text="", gbc_model=None, url_type="ACTIONABLE"):
    url = clean_url(raw_url)
    if not url:
        return None

    parsed = urlparse(url if re.match(r'^https?://', url) else 'http://' + url)
    domain = parsed.netloc.lower().split(':')[0]
    if not domain or '.' not in domain:
        return None

    # Detect urlType if not explicitly passed
    if url_type == "ACTIONABLE":
        url_type = classify_url_type(url, "a")

    protocol = parsed.scheme.upper() if parsed.scheme else 'HTTP'
    is_https = (protocol == 'HTTPS')
    reg_dom = get_registered_domain(domain)
    is_trusted = is_trusted_service(domain)
    is_inst = is_institutional_domain(domain)
    is_google_auth = is_authorized_for_brand(domain, 'google')

    reasons = []
    indicators = []
    risk_score = 0

    # If it is an image/resource URL, exclude from phishing detection
    if url_type in ["IMAGE_RESOURCE", "TRACKING_RESOURCE", "CSS_RESOURCE", "EMAIL_RENDERING_RESOURCE"]:
        print(f"[InnoveXShield URL] Resource URL ignored ({url_type}): {url}")
        return {
            'anchorText': anchor_text or url,
            'originalUrl': url,
            'domain': domain,
            'protocol': protocol,
            'https': is_https,
            'urlType': url_type,
            'riskScore': 0,
            'verdict': 'SAFE',
            'mlPrediction': 'LEGITIMATE',
            'mlProbability': 0.0,
            'featuresList': [1] * 30,
            'featuresDict': {},
            'reasons': [f"Embedded email resource / CDN asset ({url_type}) - excluded from phishing analysis"],
            'indicators': []
        }

    # 1. 30-Feature Extraction using trained model feature definitions
    feature_vector = [1] * 30
    features_dict = {}
    ml_prediction = "LEGITIMATE"
    ml_probability = 0.0

    try:
        from feature import FeatureExtraction, FEATURE_NAMES
        fe = FeatureExtraction(url)
        feature_vector = fe.getFeaturesList()
        features_dict = fe.getFeaturesDict()

        if gbc_model:
            pred = gbc_model.predict([feature_vector])[0]
            probs = gbc_model.predict_proba([feature_vector])[0]
            # classes are [-1, 1] where -1 is Phishing (index 0) and 1 is Legitimate (index 1)
            raw_pred = int(pred)
            ml_phish_prob = float(probs[0])
            ml_legit_prob = float(probs[1])
            ml_probability = ml_phish_prob

            if raw_pred == -1 and not is_trusted and not is_inst:
                ml_prediction = "PHISHING"
                risk_score = max(risk_score, int(ml_phish_prob * 85))
                reasons.append(f"Trained Gradient Boosting model classified URL as Phishing ({int(ml_phish_prob * 100)}% confidence)")
                indicators.append({
                    "type": "URL",
                    "severity": "HIGH",
                    "message": f"The URL '{domain}' was classified as phishing by the trained Gradient Boosting model."
                })
            else:
                ml_prediction = "LEGITIMATE"
                if is_google_auth:
                    reasons.append("Verified Google domain / infrastructure")
                elif is_trusted:
                    reasons.append(f"Verified email service provider / delivery route ({reg_dom})")
                elif is_inst:
                    reasons.append("Verified academic / institutional domain")
                else:
                    reasons.append("Gradient Boosting model verified legitimate structure")
            
            print(f"[InnoveXShield ML] URL: {url} | Raw: {raw_pred} | Mapped: {ml_prediction} | Phish Prob: {ml_phish_prob:.4f} | Legit Prob: {ml_legit_prob:.4f}")
    except Exception as e:
        print(f"[InnoveXShield ML] Feature extraction error for {url}: {e}")

    # 2. Protocol check (HTTP adds a low advisory risk, never flags phishing on its own)
    protocol_risk = "LOW" if not is_https else "NONE"
    if not is_https:
        risk_score += 10
        reasons.append("Unencrypted HTTP protocol used")
        indicators.append({
            "type": "URL",
            "severity": "LOW",
            "message": f"URL '{url}' uses unencrypted HTTP protocol."
        })

    # 3. IP Address check
    try:
        ipaddress.ip_address(domain)
        risk_score += 65
        reasons.append("Raw IP address used instead of domain name")
        indicators.append({
            "type": "URL",
            "severity": "HIGH",
            "message": f"Raw IP address '{domain}' used instead of hostname."
        })
    except Exception:
        pass

    # 4. Shortener check (exempt trusted forms/services)
    if re.search(SHORTENERS_REGEX, url, re.IGNORECASE) and not is_trusted:
        risk_score += 35
        reasons.append("URL shortener / masked redirect service detected")
        indicators.append({
            "type": "URL",
            "severity": "MEDIUM",
            "message": f"URL shortener or redirect masking service detected on '{domain}'."
        })

    # 5. Punycode check
    if 'xn--' in domain:
        risk_score += 45
        reasons.append("Punycode / Internationalized lookalike domain detected")
        indicators.append({
            "type": "DOMAIN",
            "severity": "HIGH",
            "message": f"Punycode lookalike domain detected ('{domain}')."
        })

    # 6. Typosquatting / Brand Spoofing check (only on actual domain token mismatch, never from anchor text)
    domain_tokens = re.split(r'[.-]', domain)
    brand_spoofed = False
    
    if not is_trusted and not is_inst:
        for brand in KNOWN_BRANDS:
            # If domain is authorized for this brand, skip impersonation check
            if is_authorized_for_brand(domain, brand):
                continue
            for part in domain_tokens:
                clean_part = part
                for k, v in TYPOS_MAP.items():
                    clean_part = clean_part.replace(k, v)
                is_typo_replacement = (part != clean_part and clean_part == brand)
                dist = levenshtein(clean_part, brand)
                if is_typo_replacement or (dist == 1 and clean_part != brand):
                    risk_score += 70
                    reasons.append(f"Lookalike domain / typosquatting of brand '{brand}'")
                    indicators.append({
                        "type": "DOMAIN",
                        "severity": "HIGH",
                        "message": f"Domain '{domain}' is a lookalike / typosquatting impersonation of '{brand}'."
                    })
                    brand_spoofed = True
                    break
                if brand in clean_part and not is_authorized_for_brand(domain, brand):
                    risk_score += 65
                    reasons.append(f"Brand impersonation of '{brand}' on unofficial domain")
                    indicators.append({
                        "type": "DOMAIN",
                        "severity": "HIGH",
                        "message": f"Brand impersonation of '{brand}' embedded in unauthorized domain '{domain}'."
                    })
                    brand_spoofed = True
                    break
            if brand_spoofed:
                break

    # 7. Deep subdomains check
    if not is_trusted:
        subdomains = domain[:-len(reg_dom)].strip('.') if domain.endswith(reg_dom) else domain
        subdomain_levels = len(subdomains.split('.')) if subdomains else 0
        if subdomain_levels > 2:
            risk_score += 20
            reasons.append("Excessive subdomains detected (obfuscation pattern)")

    # 8. Suspicious keywords in path
    if not is_trusted and not is_inst:
        path_query = (parsed.path + '?' + parsed.query).lower()
        matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_query]
        if matched_kws:
            risk_score += 15
            reasons.append(f"Suspicious authentication/security keywords in path: {', '.join(matched_kws[:3])}")

    # Cap risk score
    risk_score = min(max(risk_score, 0), 100)

    if risk_score >= 65 or ml_prediction == "PHISHING":
        verdict = "MALICIOUS"
    elif risk_score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        if not reasons:
            reasons.append("Legitimate domain structure with valid formatting")

    return {
        'anchorText': anchor_text or url,
        'anchorTextMismatch': 'IGNORED',
        'originalUrl': url,
        'domain': domain,
        'protocol': protocol,
        'protocolRisk': protocol_risk,
        'https': is_https,
        'urlType': url_type,
        'riskScore': risk_score,
        'verdict': verdict,
        'mlPrediction': ml_prediction,
        'mlProbability': round(ml_probability, 4),
        'featuresList': feature_vector,
        'featuresDict': features_dict,
        'reasons': reasons,
        'indicators': indicators
    }

def analyze_sender(sender_str, reply_to=""):
    if not sender_str:
        return {
            'email': '',
            'domain': '',
            'displayName': '',
            'suspicious': False,
            'reasons': [],
            'indicators': []
        }
    
    sender_str = sender_str.strip()
    reasons = []
    indicators = []
    suspicious = False

    match = re.search(r'(.*?)\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>', sender_str)
    if match:
        display_name = match.group(1).replace('"', '').strip()
        email_addr = match.group(2).lower()
    else:
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', sender_str)
        email_addr = email_match.group(0).lower() if email_match else sender_str
        display_name = ""

    domain = email_addr.split('@')[-1] if '@' in email_addr else ""

    # Check 1: Display Name vs Sender Domain Impersonation
    if display_name:
        for brand in KNOWN_BRANDS:
            if brand in display_name.lower():
                # Only flag if domain is NOT authorized for that brand!
                if domain and not is_authorized_for_brand(domain, brand):
                    suspicious = True
                    msg = f"Sender display name claims to be '{display_name}' but actual email is from unofficial domain '{domain}' (Display Name Spoofing)."
                    reasons.append(msg)
                    indicators.append({
                        "type": "DOMAIN",
                        "severity": "HIGH",
                        "message": msg
                    })

    # Check 2: Sender domain typosquatting
    if domain:
        domain_tokens = re.split(r'[.-]', domain)
        for brand in KNOWN_BRANDS:
            if is_authorized_for_brand(domain, brand):
                continue
            for part in domain_tokens:
                clean_part = part
                for k, v in TYPOS_MAP.items():
                    clean_part = clean_part.replace(k, v)
                is_typo_replacement = (part != clean_part and clean_part == brand)
                dist = levenshtein(clean_part, brand)
                if is_typo_replacement or (dist == 1 and clean_part != brand):
                    suspicious = True
                    msg = f"Sender domain '{domain}' uses lookalike / typosquatted brand name '{brand}'."
                    reasons.append(msg)
                    indicators.append({
                        "type": "DOMAIN",
                        "severity": "HIGH",
                        "message": msg
                    })
                    break

    # Check 3: Reply-To Mismatch
    if reply_to and domain:
        reply_domain = reply_to.split('@')[-1].lower() if '@' in reply_to else ""
        if reply_domain and reply_domain != domain:
            suspicious = True
            msg = f"Reply-To address '{reply_to}' does not match sender domain '{domain}'."
            reasons.append(msg)
            indicators.append({
                "type": "DOMAIN",
                "severity": "MEDIUM",
                "message": msg
            })

    return {
        'email': email_addr,
        'domain': domain,
        'displayName': display_name,
        'suspicious': suspicious,
        'reasons': reasons,
        'indicators': indicators
    }

def analyze_email_text(subject, body_text):
    indicators = []
    content_risk = 0
    full_text = f"{subject or ''}\n{body_text or ''}"

    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            matched_phrase = match.group(0)
            if any(k in matched_phrase.lower() for k in ['suspend', 'terminat', 'deactivat', 'block']):
                content_risk += 25
                indicators.append({
                    "type": "CONTENT",
                    "severity": "HIGH",
                    "message": "Email contains urgent account suspension or termination threats."
                })
            elif any(k in matched_phrase.lower() for k in ['urgent', 'immediately', 'immediate action', 'warning']):
                content_risk += 20
                indicators.append({
                    "type": "CONTENT",
                    "severity": "MEDIUM",
                    "message": "Email uses high-urgency language demanding immediate action."
                })
            elif any(k in matched_phrase.lower() for k in ['unauthorized', 'suspicious', 'fraudulent']):
                content_risk += 20
                indicators.append({
                    "type": "CONTENT",
                    "severity": "MEDIUM",
                    "message": "Email uses false security alerts claiming unauthorized activity."
                })
            elif any(k in matched_phrase.lower() for k in ['verify', 'confirm', 'validate']):
                content_risk += 25
                indicators.append({
                    "type": "CONTENT",
                    "severity": "HIGH",
                    "message": "Email requests immediate verification of sensitive account credentials or identity."
                })
            elif any(k in matched_phrase.lower() for k in ['password', 'credential', 'passcode', 'pin']):
                content_risk += 25
                indicators.append({
                    "type": "CONTENT",
                    "severity": "HIGH",
                    "message": "Email requests password reset or credential submission."
                })
            elif any(k in matched_phrase.lower() for k in ['winner', 'bitcoin', 'lottery', 'inheritance']):
                content_risk += 25
                indicators.append({
                    "type": "CONTENT",
                    "severity": "MEDIUM",
                    "message": "Email presents financial reward or lottery claim lure."
                })
            elif any(k in matched_phrase.lower() for k in ['invoice', 'overdue', 'payment']):
                content_risk += 15
                indicators.append({
                    "type": "CONTENT",
                    "severity": "LOW",
                    "message": "Email references overdue payment or invoice alert."
                })

    return content_risk, indicators

def investigate_email(email_data, gbc_model=None):
    """
    Complete Phishing Investigation Pipeline:
    1. Parse email (Sender, Subject, Body, URLs)
    2. Separate Actionable URLs vs Resource/Image URLs
    3. Extract 30 features per actionable URL using trained GBC feature definitions
    4. Run GBC model.predict() and model.predict_proba()
    5. Perform secondary email-level security analysis
    6. Aggregate risk engine & produce structured JSON output
    """
    sender_raw = email_data.get('sender', '') or email_data.get('from', '') or ''
    reply_to = email_data.get('reply_to', '') or ''
    subject = email_data.get('subject', '') or ''
    body_text = email_data.get('body', '') or email_data.get('text', '') or ''
    body_html = email_data.get('html', '') or ''
    provided_links = email_data.get('links', [])

    print(f"\n[InnoveXShield Debug] === EMAIL DETECTION ===")
    print(f"[InnoveXShield Debug] Sender: {sender_raw}")
    print(f"[InnoveXShield Debug] Subject: {subject}")

    # 1. Sender Analysis
    sender_analysis = analyze_sender(sender_raw, reply_to)
    sender_domain = sender_analysis.get('domain', '')
    is_google_sender = is_authorized_for_brand(sender_domain, 'google')

    # 2. Extract and Deduplicate all URLs
    combined_content = f"{body_html}\n{body_text}"
    extracted_urls = extract_urls_from_content(combined_content)

    if provided_links:
        for pl in provided_links:
            if isinstance(pl, dict):
                p_url = clean_url(pl.get('url', ''))
                p_anchor = pl.get('anchorText', p_url)
                p_elem = pl.get('elementType', 'a')
                p_type = pl.get('urlType', classify_url_type(p_url, p_elem))
            else:
                p_url = clean_url(str(pl))
                p_anchor = p_url
                p_elem = 'a'
                p_type = classify_url_type(p_url, 'a')
            
            matched = False
            for ex in extracted_urls:
                if ex['url'] == p_url:
                    if p_anchor:
                        ex['anchorText'] = p_anchor
                    matched = True
                    break
            if not matched and p_url:
                extracted_urls.append({
                    'url': p_url,
                    'anchorText': p_anchor,
                    'elementType': p_elem,
                    'urlType': p_type
                })

    # 3. Separate Actionable URLs from Resource URLs
    actionable_items = []
    resource_items = []

    for item in extracted_urls:
        url = item['url']
        url_type = item.get('urlType', classify_url_type(url, item.get('elementType', 'a')))
        if url_type == "ACTIONABLE":
            actionable_items.append(item)
        else:
            resource_items.append(item)

    print(f"[InnoveXShield Debug] Total URLs found: {len(extracted_urls)} | Actionable: {len(actionable_items)} | Resources ignored: {len(resource_items)}")

    # 4. Analyze each Actionable URL using 30-feature extraction & GBC Model
    analyzed_links = []
    max_link_risk = 0
    malicious_links_count = 0
    suspicious_links_count = 0
    all_indicators = []
    reasons_list = []

    overall_ml_prediction = "LEGITIMATE"
    highest_ml_phish_prob = 0.0
    all_actionable_are_google = (len(actionable_items) > 0)

    for item in actionable_items:
        link_result = analyze_single_url(item['url'], item.get('anchorText', ''), gbc_model, "ACTIONABLE")
        if link_result:
            analyzed_links.append(link_result)
            max_link_risk = max(max_link_risk, link_result['riskScore'])
            all_indicators.extend(link_result.get('indicators', []))
            reasons_list.extend(link_result.get('reasons', []))

            if link_result.get('mlProbability', 0.0) > highest_ml_phish_prob:
                highest_ml_phish_prob = link_result.get('mlProbability', 0.0)

            if link_result['verdict'] == 'MALICIOUS' or link_result.get('mlPrediction') == 'PHISHING':
                malicious_links_count += 1
                overall_ml_prediction = "PHISHING"
            elif link_result['verdict'] == 'SUSPICIOUS':
                suspicious_links_count += 1

            if not is_authorized_for_brand(link_result['domain'], 'google'):
                all_actionable_are_google = False

    # Also analyze resource items for clean reporting (without risk contribution)
    for item in resource_items:
        res_link = analyze_single_url(item['url'], item.get('anchorText', ''), gbc_model, item.get('urlType', 'IMAGE_RESOURCE'))
        if res_link:
            analyzed_links.append(res_link)

    # 5. Email-level Content Analysis
    content_risk, content_indicators = analyze_email_text(subject, body_text)
    
    # If email is from authorized Google sender and all actionable links are Google domains, suppress false security alert urgency
    if is_google_sender and all_actionable_are_google and not sender_analysis['suspicious'] and malicious_links_count == 0:
        content_risk = 0
        content_indicators = []

    all_indicators.extend(sender_analysis.get('indicators', []))
    all_indicators.extend(content_indicators)
    reasons_list.extend(sender_analysis.get('reasons', []))

    # 6. Handle "No Actionable URL" Edge Case
    urls_analyzed = len(actionable_items)
    resource_urls_ignored = len(resource_items)
    suspicious_urls = malicious_links_count + suspicious_links_count

    if urls_analyzed == 0:
        all_indicators.append({
            "type": "URL",
            "severity": "INFO",
            "message": "No actionable URL was available for the trained website-based ML model; email-level analysis was used instead."
        })

    # 7. Overall Risk Calculation & Classification
    if urls_analyzed > 0:
        if is_google_sender and all_actionable_are_google and not sender_analysis['suspicious'] and malicious_links_count == 0:
            total_risk = 0
            classification = "LEGITIMATE"
            confidence = 99
            recommended_action = "SAFE_TO_OPEN"
            risk_level = "LOW"
            explanation = "The email uses a trusted Google sender domain and its actionable links resolve to Google domains. Embedded Google CDN/resource URLs were excluded from phishing-link analysis."
        else:
            if malicious_links_count > 0:
                total_risk = max(75, max_link_risk, int(highest_ml_phish_prob * 100))
            elif sender_analysis['suspicious'] and content_risk >= 20:
                total_risk = max(70, content_risk + 35)
            elif suspicious_links_count > 0:
                total_risk = max(45, max_link_risk + int(content_risk * 0.3))
            elif sender_analysis['suspicious']:
                total_risk = max(40, content_risk + 20)
            else:
                total_risk = min(content_risk, 30)

            if total_risk >= 65 or overall_ml_prediction == "PHISHING":
                classification = "PHISHING"
                confidence = min(max(total_risk, int(highest_ml_phish_prob * 100), 75), 98)
                recommended_action = "DO_NOT_CLICK"
                risk_level = "HIGH"
                explanation = (
                    f"The email is classified as PHISHING with {confidence}% confidence. "
                    f"Trained Gradient Boosting model and email security analysis detected significant threat indicators."
                )
            elif total_risk >= 35:
                classification = "SUSPICIOUS"
                confidence = min(max(total_risk + 10, 50), 75)
                recommended_action = "PROCEED_WITH_CAUTION"
                risk_level = "MEDIUM"
                explanation = (
                    f"The email is classified as SUSPICIOUS with {confidence}% confidence. "
                    f"Caution is advised when interacting with links or sender."
                )
            else:
                classification = "LEGITIMATE"
                confidence = min(max(100 - total_risk, 80), 99)
                recommended_action = "SAFE_TO_OPEN"
                risk_level = "LOW"
                explanation = (
                    f"The email appears to be LEGITIMATE with {confidence}% confidence. "
                    f"All {urls_analyzed} actionable links and sender credentials passed verification."
                )
    else:
        # No actionable URL present: purely email-level signals
        if sender_analysis['suspicious'] or content_risk > 0:
            total_risk = max(55, content_risk + (30 if sender_analysis['suspicious'] else 0))
            classification = "SUSPICIOUS"
            confidence = 65
            recommended_action = "PROCEED_WITH_CAUTION"
            risk_level = "MEDIUM"
            explanation = "No URL was available for the trained website-based ML model; email-level analysis was used instead."
        else:
            total_risk = 0
            classification = "LEGITIMATE"
            confidence = 90
            recommended_action = "SAFE_TO_OPEN"
            risk_level = "LOW"
            explanation = "No URL was available for the trained website-based ML model; email-level analysis was used instead."

    # Deduplicate indicators & reasons
    unique_indicators = []
    seen_msgs = set()
    for ind in all_indicators:
        if ind['message'] not in seen_msgs:
            seen_msgs.add(ind['message'])
            unique_indicators.append(ind)

    reasons_list = list(dict.fromkeys(reasons_list))
    if not reasons_list and classification == "LEGITIMATE":
        reasons_list.append("Sender domain and content exhibit normal communication characteristics.")
        reasons_list.append("Gradient Boosting ML model verified legitimate website structures.")

    print(f"[InnoveXShield Debug] === FINAL DECISION ===")
    print(f"[InnoveXShield Debug] Classification: {classification} | Risk: {total_risk}/100 | Confidence: {confidence}%")

    return {
        "classification": classification,
        "risk_score": total_risk,
        "confidence": confidence,
        "ml_prediction": overall_ml_prediction,
        "ml_probability": round(highest_ml_phish_prob, 4),
        "sender": sender_analysis.get('email', sender_raw),
        "sender_domain": sender_domain,
        "subject": subject,
        "urls_analyzed": urls_analyzed,
        "actionable_urls": urls_analyzed,
        "resource_urls_ignored": resource_urls_ignored,
        "suspicious_urls": suspicious_urls,
        "suspicious_actionable_urls": suspicious_urls,
        "indicators": unique_indicators,
        "recommended_action": recommended_action,

        # Backwards compatible fields
        "emailVerdict": classification,
        "riskLevel": risk_level,
        "overallRiskScore": total_risk,
        "senderAnalysis": sender_analysis,
        "detectedLinks": analyzed_links,
        "reasons": reasons_list,
        "explanation": explanation
    }


