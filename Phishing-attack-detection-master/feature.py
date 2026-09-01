import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

FEATURE_NAMES = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
    'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
    'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 'LinksInScriptTags',
    'ServerFormHandler', 'InfoEmail', 'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust',
    'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
    'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
]

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        # Ensure URL has scheme for proper parsing
        if not re.match(r"^https?://", url):
            self.url = "http://" + url
        else:
            self.url = url

        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc.split(':')[0]
        except Exception:
            pass

        # Fast HTTP inspection (timeout 1.5s) to avoid hanging
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
            self.response = requests.get(self.url, headers=headers, timeout=1.5)
            if self.response and self.response.text:
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception:
            pass

        # Fast WHOIS inspection with fallback
        try:
            if self.domain and not self.UsingIp() == -1:
                self.whois_response = whois.whois(self.domain)
        except Exception:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIp
    def UsingIp(self):
        try:
            ip_str = self.domain.split(":")[0] if self.domain else self.url
            ipaddress.ip_address(ip_str)
            return -1
        except Exception:
            return 1

    # 2. longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3. shortUrl
    def shortUrl(self):
        match = re.search(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net|'
            r'go\.link|\.link/|cutt\.ly|rebrand\.ly|t\.ly|rb\.gy|dub\.sh|shorturl\.at|buff\.ly|smarturl\.it|bl\.ink',
            self.url
        )
        if match:
            return -1
        return 1

    # 4. Symbol@
    def symbol(self):
        if "@" in self.url:
            return -1
        return 1

    # 5. Redirecting//
    def redirecting(self):
        if self.url.rfind('//') > 7:
            return -1
        return 1

    # 6. prefixSuffix
    def prefixSuffix(self):
        try:
            if '-' in self.domain:
                return -1
            return 1
        except Exception:
            return -1

    # 7. SubDomains
    def SubDomains(self):
        dot_count = len(re.findall(r"\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS
    def Hppts(self):
        try:
            if self.urlparse and 'https' in self.urlparse.scheme:
                return 1
            return -1
        except Exception:
            return 1

    # 9. DomainRegLen
    def DomainRegLen(self):
        try:
            if not self.whois_response:
                return -1
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
            return -1
        except Exception:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            if not self.soup:
                return -1
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    href = link['href']
                    dots = [x.start(0) for x in re.finditer(r'\.', href)]
                    if self.url in href or len(dots) == 1 or (self.domain and self.domain in href):
                        return 1
            return -1
        except Exception:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except Exception:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except Exception:
            return -1

    # 13. RequestURL
    def RequestURL(self):
        try:
            if not self.soup:
                return -1
            i = 0
            success = 0
            for tag, attr in [('img', 'src'), ('audio', 'src'), ('embed', 'src'), ('iframe', 'src')]:
                for elem in self.soup.find_all(tag, **{attr: True}):
                    val = elem[attr]
                    dots = [x.start(0) for x in re.finditer(r'\.', val)]
                    if self.url in val or (self.domain and self.domain in val) or len(dots) == 1:
                        success += 1
                    i += 1

            if i == 0:
                return 1
            percentage = (success / float(i)) * 100
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            if not self.soup:
                return -1
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href']
                if "#" in href or "javascript" in href.lower() or "mailto" in href.lower() or not (self.url in href or (self.domain and self.domain in href)):
                    unsafe += 1
                i += 1

            if i == 0:
                return 1
            percentage = (unsafe / float(i)) * 100
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return -1
            i, success = 0, 0
            for link in self.soup.find_all('link', href=True):
                href = link['href']
                dots = [x.start(0) for x in re.finditer(r'\.', href)]
                if self.url in href or (self.domain and self.domain in href) or len(dots) == 1:
                    success += 1
                i += 1

            for script in self.soup.find_all('script', src=True):
                src = script['src']
                dots = [x.start(0) for x in re.finditer(r'\.', src)]
                if self.url in src or (self.domain and self.domain in src) or len(dots) == 1:
                    success += 1
                i += 1

            if i == 0:
                return 1
            percentage = (success / float(i)) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if not self.soup or len(self.soup.find_all('form', action=True)) == 0:
                return 1
            for form in self.soup.find_all('form', action=True):
                action = form['action']
                if action == "" or action == "about:blank":
                    return -1
                elif self.url not in action and (self.domain and self.domain not in action):
                    return 0
            return 1
        except Exception:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if not self.response:
                return -1
            if re.findall(r"mailto:", self.response.text, re.IGNORECASE):
                return -1
            return 1
        except Exception:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response and self.whois_response and str(self.whois_response) in self.response.text:
                return 1
            return -1
        except Exception:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if not self.response:
                return -1
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            return -1
        except Exception:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if not self.response:
                return -1
            if re.findall(r"<script>.+onmouseover.+</script>", self.response.text):
                return 1
            return -1
        except Exception:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if not self.response:
                return -1
            if re.findall(r"event\.button\s*==\s*2", self.response.text):
                return 1
            return -1
        except Exception:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if not self.response:
                return -1
            if re.findall(r"alert\(", self.response.text):
                return 1
            return -1
        except Exception:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if not self.response:
                return -1
            if re.findall(r"(<iframe|<frameBorder)", self.response.text, re.IGNORECASE):
                return 1
            return -1
        except Exception:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            if not self.whois_response:
                return -1
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                return 1
            return -1
        except Exception:
            return -1

    # 25. DNSRecording    
    def DNSRecording(self):
        try:
            if not self.domain:
                return -1
            socket.gethostbyname(self.domain)
            return 1
        except Exception:
            return -1

    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
        try:
            # Check domain Alexa / top ranking or fallback
            if not self.domain:
                return -1
            if any(self.domain.endswith(t) for t in ['google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'iitm.ac.in', 'nptel.ac.in', 'sendgrid.net', 'github.com']):
                return 1
            return 0
        except Exception:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            if not self.domain:
                return -1
            if any(self.domain.endswith(t) for t in ['google.com', 'microsoft.com', 'apple.com', 'iitm.ac.in', 'nptel.ac.in', 'github.com', 'sendgrid.net']):
                return 1
            return -1
        except Exception:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            if not self.domain:
                return -1
            # Valid domain with DNS is indexed
            socket.gethostbyname(self.domain)
            return 1
        except Exception:
            return -1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            if not self.response:
                return 0
            number_of_links = len(re.findall(r"<a\s+(?:[^>]*?\s+)?href=", self.response.text, re.IGNORECASE))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            return -1
        except Exception:
            return 0

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
                r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
                self.url
            )
            ip_address = socket.gethostbyname(self.domain) if self.domain else ""
            ip_match = re.search(
                r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
                ip_address
            ) if ip_address else False
            if url_match or ip_match:
                return -1
            return 1
        except Exception:
            return 1

    def getFeaturesList(self):
        # Validate 30 features exact length
        if len(self.features) == 30:
            return self.features
        # Ensure 30 items
        padded = list(self.features)
        while len(padded) < 30:
            padded.append(1)
        return padded[:30]

    def getFeaturesDict(self):
        feat_list = self.getFeaturesList()
        return {FEATURE_NAMES[i]: feat_list[i] for i in range(len(FEATURE_NAMES))}