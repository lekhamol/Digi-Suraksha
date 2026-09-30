import re
import math
import urllib.parse
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# Top popular brands susceptible to impersonation
TARGET_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "netflix", "facebook", "instagram",
    "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe", "gpay", "whatsapp", "bankofbaroda",
    "yono", "aadhaar", "npci", "irctc", "binance", "metamask", "coinbase"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".info", ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".zip", ".mov", ".work", ".click", ".live", ".guru", ".rest", ".fit", ".icu"
]

PHISHING_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "banking", "kyc", "alert",
    "blocked", "suspended", "confirm", "wallet", "support", "signin", "free", "gift",
    "reward", "lottery", "claim", "urgent", "action-required", "otp", "passcode"
]

SMS_SCAM_PATTERNS = [
    (r"\b(kyc|aadhaar|pan)\s*(update|expire|block|verify)\b", "Urgent KYC / Account verification scam", 35),
    (r"\b(account|card|atm)\s*(suspended|blocked|deactivated|restricted)\b", "Account Suspension / Security Panic Tactic", 30),
    (r"\b(win|won|congratulations|selected|lottery|prize|reward|claim|cashback)\b", "Lottery / Prize / Financial Bait Scam", 25),
    (r"\b(click|visit|link|open)\s*(here|now|http|bit\.ly|tinyurl)\b", "Suspicious Link Click Incentive", 20),
    (r"\b(otp|pin|password|cvv)\s*(share|send|enter|verify)\b", "Credential / OTP Harvesting Attempt", 40),
    (r"\b(urgent|immediately|within 24 hours|today only|action required)\b", "Psychological Pressure / Artificial Urgency", 15)
]

def calculate_entropy(string):
    """Calculates Shannon Entropy to measure randomness in string (e.g. domain name)."""
    if not string:
        return 0.0
    prob = [float(string.count(c)) / len(string) for c in set(string)]
    return - sum([p * math.log2(p) for p in prob])

def levenshtein_distance(s1, s2):
    """Calculates distance between two strings to detect typosquatting."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
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

class ThreatEngine:
    def __init__(self):
        # Initialize ML model for SMS/Text Classification
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        self.ml_classifier = MultinomialNB()
        self._train_ml_model()

    def _train_ml_model(self):
        """Train light Naive Bayes model on synthetic security corpus."""
        training_corpus = [
            # Phishing / Scam samples
            ("URGENT: Your SBI bank account will be blocked today. Click http://sbi-update-kyc.info to update PAN", 1),
            ("Congratulations! You won Rs 50,000 Paytm cashback. Claim now at http://bit.ly/claim-paytm", 1),
            ("Your Netflix payment failed. Update credit card immediately to avoid suspension http://netflix-pay.xyz", 1),
            ("Dear customer, your ELECTRICITY bill is unpaid. Power cut at 9 PM. Call officer 9876543210", 1),
            ("Dear user, suspicious login from Russia on your Google Account. Verify identity at http://google-security-verify.net", 1),
            ("ALERT: Your Amazon package is delayed. Pay re-delivery fee of $1 at http://amazon-tracking.online", 1),
            ("Important: Share your OTP 482910 to confirm loan disbursement from HDFC Bank.", 1),
            ("Your WhatsApp code is 123-456. Do not share this with anyone.", 1),
            ("Get free iPhone 15 Pro by completing this short survey! Click http://free-gifts.click", 1),
            ("Work from home & earn 5000 daily with no investment. Contact HR on WhatsApp link http://job-now.site", 1),
            
            # Legitimate / Safe samples
            ("Hi John, are we still meeting for lunch today at 1 PM?", 0),
            ("Your OTP for HDFC netbanking login is 849302. Valid for 10 mins. Do not share.", 0),
            ("Your order #84920 has been shipped via BlueDart. Track at https://www.amazon.in/orders", 0),
            ("Flight status update: AI-102 to Delhi is on schedule at 18:30 from Terminal 2.", 0),
            ("Hey mom, please send the recipe for dinner when you get a chance.", 0),
            ("Meeting reminder: Team sync starts in 15 minutes on Google Meet.", 0),
            ("Your monthly electricity statement is generated. Amount: 1420 INR. Due date 15th Oct.", 0),
            ("Thank you for dining at Taj Restaurant. We value your feedback!", 0),
            ("Security notification: New sign in to GitHub from Windows Chrome in Mumbai.", 0)
        ]
        
        texts = [item[0] for item in training_corpus]
        labels = [item[1] for item in training_corpus]
        
        X = self.vectorizer.fit_transform(texts)
        self.ml_classifier.fit(X, labels)

    def analyze_url(self, raw_url):
        """Analyzes URL for phishing indicators, typosquatting, entropy, and malicious structural patterns."""
        url = raw_url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            path = parsed.path.lower()
        except Exception:
            return {
                "url": raw_url,
                "risk_score": 90,
                "risk_level": "HIGH",
                "indicators": ["Malformed or invalid URL structure"],
                "reasons": ["The provided string does not form a valid URL structure."],
                "recommendation": "Do not attempt to open this URL."
            }

        risk_score = 0
        indicators = []
        reasons = []

        # 1. Scheme Check (HTTP vs HTTPS)
        if parsed.scheme == "http":
            risk_score += 15
            indicators.append("Unencrypted Protocol (HTTP)")
            reasons.append("The site does not use HTTPS encryption, making login credentials vulnerable to interception.")

        # 2. IP Address Hostname
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, hostname):
            risk_score += 35
            indicators.append("IP Address Hostname")
            reasons.append("Legitimate websites rarely use bare IP addresses instead of domain names. This is common in phishing attacks.")

        # 3. Suspicious Top-Level Domain (TLD)
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                risk_score += 25
                indicators.append(f"High-Risk TLD ({tld})")
                reasons.append(f"The top-level domain '{tld}' has a high statistical correlation with malicious phishing disposable domains.")
                break

        # 4. Brand Impersonation & Typosquatting
        domain_parts = hostname.split('.')
        main_domain = domain_parts[-2] if len(domain_parts) >= 2 else hostname

        for brand in TARGET_BRANDS:
            # Exact presence in subdomain/path but not exact domain name
            if brand in hostname and not hostname.endswith(f"{brand}.com") and not hostname.endswith(f"{brand}.in") and not hostname.endswith(f"{brand}.org") and not hostname.endswith(f"{brand}.net"):
                risk_score += 35
                indicators.append(f"Brand Impersonation ({brand.capitalize()})")
                reasons.append(f"The URL contains the brand name '{brand.capitalize()}' in a suspicious domain pattern ({hostname}), attempting to look official.")
                break

            # Levenshtein Typosquatting Check (e.g. paypa1, g00gle)
            dist = levenshtein_distance(main_domain, brand)
            if dist == 1 and main_domain != brand:
                risk_score += 40
                indicators.append(f"Typosquatting Detected ({main_domain} vs {brand})")
                reasons.append(f"The domain '{main_domain}' is slightly misspelled compared to official '{brand}'. This tricks users into visiting a lookalike fake site.")
                break

        # 5. Shannon Entropy (Randomness test)
        entropy = calculate_entropy(hostname)
        if entropy > 3.8 and len(hostname) > 15:
            risk_score += 20
            indicators.append("High Domain Entropy (Random String)")
            reasons.append(f"Domain entropy is high ({entropy:.2f}), indicating auto-generated random character sequence often used by malware/phishing bots.")

        # 6. Phishing Keyword Check in Path/Query
        matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
        if matched_keywords:
            risk_score += min(30, len(matched_keywords) * 10)
            indicators.append(f"Suspicious Security Keywords ({', '.join(matched_keywords[:3])})")
            reasons.append(f"URL contains action triggers commonly found in phishing pages: {', '.join(matched_keywords)}.")

        # 7. Subdomain Flooding (e.g., login.bank.secure.update.attacker.com)
        if len(domain_parts) > 3:
            risk_score += 15
            indicators.append("Excessive Subdomains")
            reasons.append("Multiple nested subdomains are often used to hide the true root domain name on mobile devices.")

        # Cap score 0-100
        risk_score = min(100, risk_score)
        
        # Risk level determination
        if risk_score >= 70:
            risk_level = "CRITICAL" if risk_score >= 85 else "HIGH"
            recommendation = "DANGER: Do NOT click this link or enter any sensitive personal data. This link displays strong phishing traits."
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            recommendation = "WARNING: Exercise extreme caution. Verify the sender or domain authenticity before interacting."
        else:
            risk_level = "LOW"
            recommendation = "SAFE: No major suspicious structural anomalies detected. Standard web browsing safety rules apply."

        return {
            "url": raw_url,
            "parsed_domain": hostname,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators if indicators else ["No structural threat indicators found"],
            "reasons": reasons if reasons else ["URL follows typical legitimate domain registration and protocol practices."],
            "recommendation": recommendation,
            "entropy": round(entropy, 2)
        }

    def analyze_message(self, message_text):
        """Analyzes SMS / Email / Chat text for scam triggers using Heuristics + NLP ML Model."""
        text = message_text.strip()
        if not text:
            return {"error": "Empty message text provided"}

        risk_score = 0
        indicators = []
        reasons = []

        # 1. Regex Pattern Scans
        for pattern, label, weight in SMS_SCAM_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                risk_score += weight
                indicators.append(label)
                reasons.append(f"Detected pattern associated with '{label}'.")

        # 2. Embedded Link Analysis
        urls = re.findall(r'https?://[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+', text)
        url_analyses = []
        if urls:
            risk_score += 20
            indicators.append(f"Embedded Links Detected ({len(urls)})")
            for u in urls:
                res = self.analyze_url(u)
                url_analyses.append(res)
                if res['risk_score'] > 50:
                    risk_score += 25
                    indicators.append(f"High-Risk Embedded Link: {u}")
                    reasons.append(f"Message contains link with high threat score ({res['risk_score']}%): {res['recommendation']}")

        # 3. ML NLP Model Prediction
        try:
            X_text = self.vectorizer.transform([text])
            ml_prob = float(self.ml_classifier.predict_proba(X_text)[0][1]) * 100
            if ml_prob > 50:
                risk_score += int(ml_prob * 0.4)
                indicators.append(f"AI Model Threat Confidence ({ml_prob:.1f}%)")
                reasons.append(f"Natural language machine learning model evaluated message text as highly consistent with known phishing/spam vectors.")
        except Exception:
            ml_prob = 0.0

        risk_score = min(100, risk_score)

        if risk_score >= 70:
            risk_level = "CRITICAL" if risk_score >= 85 else "HIGH"
            recommendation = "ALERT: High probability of phishing or financial scam message. Do NOT click links or contact provided phone numbers."
        elif risk_score >= 35:
            risk_level = "MEDIUM"
            recommendation = "CAUTION: Message exhibits suspicious urgency or financial triggers. Verify with sender independently."
        else:
            risk_level = "LOW"
            recommendation = "SAFE: Message text appears normal with low risk characteristics."

        return {
            "message": text,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "ai_confidence": round(ml_prob, 1),
            "indicators": indicators if indicators else ["No suspicious message patterns detected"],
            "reasons": reasons if reasons else ["Text does not contain urgency flags, scam keywords, or malicious URL triggers."],
            "recommendation": recommendation,
            "url_analysis": url_analyses
        }

    def analyze_password(self, password):
        """Analyzes password strength, entropy, dictionary weakness, and leak patterns."""
        if not password:
            return {"error": "Empty password"}

        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))

        # Entropy calculation
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32

        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        common_passwords = ["123456", "password", "123456789", "12345678", "12345", "qwerty", "admin", "welcome", "india@123", "pass123"]
        is_common = password.lower() in common_passwords

        score = 0
        if length >= 8: score += 20
        if length >= 12: score += 20
        if has_upper and has_lower: score += 20
        if has_digit: score += 20
        if has_special: score += 20

        if is_common:
            score = 10
            status = "CRITICAL RISK (Leaked/Common Password)"
            advice = "This password appears in public leak databases. Change it immediately!"
        elif score >= 80:
            status = "STRONG"
            advice = "Great password! Ensures high resistance against brute-force attacks."
        elif score >= 50:
            status = "MODERATE"
            advice = "Acceptable, but consider adding special symbols or increasing length."
        else:
            status = "WEAK"
            advice = "Weak password. Vulnerable to automated dictionary and brute-force tools."

        return {
            "strength_score": score,
            "entropy_bits": round(entropy, 1),
            "status": status,
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits": has_digit,
            "has_symbols": has_special,
            "is_common_leaked": is_common,
            "recommendation": advice
        }

if __name__ == "__main__":
    engine = ThreatEngine()
    print("--- Testing URL Scanner ---")
    print(engine.analyze_url("http://paypa1-security-login.xyz/verify-account"))
    print("\n--- Testing SMS Scanner ---")
    print(engine.analyze_message("URGENT: Your SBI bank account blocked today. Click http://sbi-update.xyz to update PAN"))
