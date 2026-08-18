import re                           # for string pattern matching
import urllib.parse                 # for splitting raw URLs into components (scheme, netloc, path, params, query, fragmnet)
import tldextract                   # for splitting domain names properly
import whois                        # for looking up domain registration metadata
from datetime import datetime       # for calculating domain age

# Top-Level Domains (TLDs) commonly associated with spam
SUS_TLDS = {".xyz", ".top", ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq"}

# target keywords commonly used in phishing URLs
SUS_KEYWORDS = ["login", "verify", "secure", "update", "account", "banking", "signin", "paypal", "apple"]

# Class for analyzing URL strings against common phishing tactics
class URLAnalyzer:

    # constructor
    def __init__(self, url: str):
        # check URL starts with a valid scheme so that urllib can parse it correctly
        self.raw_url = url if url.startswith (("http://", "https://")) else f"http://{url}"
        # parse URL into the standard components 
        self.parsed = urllib.parse.urlparse(self.raw_url)
        # extract the subdomain, domain, and suffix (TLD)
        self.extracted = tldextract.extract(self.raw_url)

        self.score = 0      # risk score
        self.warnings = []  # stores warnings

    # check if host uses IPv4 address instead of domain
    def check_ip(self):
        #regex pattern match
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}"

        #extract hostname and evaluate pattern
        if re.match(ip_pattern, self.parsed.netloc.split(":")[0]):
            self.score += 40    # increase the risk score
            self.warnings.append("[HIGH] Host uses a raw IP address instead of a domain name.")

    # check if URL is high risk TLD
    def check_sus_tld(self):
        tld = f".{self.extracted.suffix}".lower()
        if tld in SUS_TLDS:
            self.score += 20    # increase risk score
            self.warnings.append(f"[MEDIUM] Domain uses high-risk TLD: {tld}")

    # check the URL for subdomain nesting and credential harvesting keywords
    def check_subdom_and_kw(self):
        subdom = self.extracted.subdomain
        subdom_count = len(subdom.split(".")) if subdom else 0      # number of subdomain levels

        # if there are excessive subdomains
        if subdom_count >= 3: 
            self.score += 15
            self.warnings.append(f"[MEDIUM] Excessive subdomains detected ({subdom_count}).")

        
        for kw in SUS_KEYWORDS:
            # check is sus keyword is in the URL string but not in the domain
            if kw in self.raw_url.lower() and kw not in self.extracted.domain:
                self.score += 15
                self.warnings.append(f"[MEDIUM] Phishing keyword '{kw}' found in subdomains or path.")   


    # check domain age
    def check_whois_age(self):
        try: 
            # query WHOIS database
            w = whois.whois(f"{self.extracted.domain}.{self.extracted.suffix}")
            created = w.creation_date

            # if the query returns a list of dates ppick the first
            if isinstance(created, list):
                created = created[0]

            if created:
                age = (datetime.now() - created).days

                if age < 30:
                    self.score += 30
                    self.warnings.append(f"[HIGH] Newly registered domain ({age} days old).")
                elif age < 180:
                    self.score += 100
                    self.warnings.append(f"[LOW] Domain is less than 6 months old ({age} days old).")
        except Exception:
            self.warnings.append("[INFO] WHOIS domain lookup unavailable or restricted.")                   

    # execute all checks and compile threat report
    def analyze(self) -> dict:
        self.check_ip()
        self.check_sus_tld()
        self.check_subdom_and_kw()
        self.check_whois_age()

        # assigning risk categories based on scores
        risk_level = "LOW"
        if self.score >= 50:
            risk_level = "HIGH / CRITICAL"
        elif self.score >= 25:
            risk_level = "MEDIUM"

        return{
            "url": self.raw_url,
            "domain": f"{self.extracted.domain}.{self.extracted.suffix}",
            "score": min(self.score, 100),           # score max is 100
            "risk_level": risk_level,
            "warnings": self.warnings
        }        