import re
import urllib.parse
import tldextract

def preprocess_url(url):
    features = []

    # Feature 1: having_IP_Address (Check if the URL contains an IP address)
    ip_pattern = r"((\d{1,3}\.){3}\d{1,3})|([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7})"
    features.append(-1 if re.search(ip_pattern, url) else 1)  # -1 = IP present (suspicious), 1 = normal domain

    # Feature 2: URL Length (Suspicious if too long)
    features.append(-1 if len(url) > 75 else (0 if len(url) > 54 else 1))

    # Feature 3: Shortening Service (Check if the URL uses a known URL shortener)
    shortening_services = ["bit.ly", "goo.gl", "tinyurl.com", "is.gd", "t.co"]
    domain = urllib.parse.urlparse(url).netloc
    features.append(-1 if any(service in domain for service in shortening_services) else 1)

    # Feature 4: having_At_Symbol (@ in URL) - Phishing Trick
    features.append(-1 if "@" in url else 1)  # -1 = Phishing, 1 = Safe

    # Feature 5: Prefix-Suffix (Check if domain contains "-")
    features.append(-1 if '-' in domain else 1)  # -1 = Phishing, 1 = Legitimate

    # Feature 6: having_Sub_Domain (Count number of dots in domain)
    ext = tldextract.extract(url)
    sub_domain_count = ext.subdomain.count('.')
    features.append(-1 if sub_domain_count >= 2 else (0 if sub_domain_count == 1 else 1))

    # Feature 7: SSLfinal_State (Check if URL uses HTTPS)
    features.append(1 if url.startswith("https://") else -1)  # -1 = No SSL, 1 = Secure

    # Feature 8: Domain Registration Length (Hardcoded, set to 0)
    features.append(0)  

    # Feature 9: Favicon (Hardcoded, set to 0)
    features.append(0)  

    # Feature 10: Request_URL (Hardcoded, set to 0)
    features.append(0)  

    # Feature 11: URL_of_Anchor (Hardcoded, set to 0)
    features.append(0)

    # Feature 12: Links_in_tags (Hardcoded, set to 0)
    features.append(0)

    # Feature 13: SFH (Hardcoded, set to 0)
    features.append(0)

    # Feature 14: Abnormal_URL (Check if domain and hostname match)
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.hostname
    features.append(-1 if hostname and ext.domain not in hostname else 1)  # -1 = Phishing

    # Feature 15: Redirect (Check number of "//" in URL)
    if url.startswith("http://") or url.startswith("https://"):
        url_without_protocol = url.split("//", 1)[1]  # Remove protocol part
        features.append(-1 if url_without_protocol.count('//') > 0 else 1)  # -1 = Redirect detected
    else:
        features.append(1)  # No redirect

    # Feature 16-25: Hardcoded values
    features += [0] * 9  # Features 16-24 (all 0)
    features.append(0)  # Feature 25: Statistical_report

    # Ensure the feature list has exactly 25 elements
    if len(features) < 25:
        missing_count = 25 - len(features)
        features += [1] * missing_count  # Append default values

    return features
