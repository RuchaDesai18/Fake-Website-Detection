"""FraudShield v2 runtime. Same JSON contract as v1 so the existing frontend works unchanged."""
import os, numpy as np, joblib
from sklearn.feature_extraction.text import HashingVectorizer
from features import extract, text_for_ngrams, FEATURE_NAMES, SHORTENERS, OFFICIAL

BASE = os.path.dirname(os.path.abspath(__file__)); _B = None
_HV = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2**19, alternate_sign=False, norm=None, dtype=np.float32)
# Platforms where ANYONE can publish a page. The platform's name says nothing about the page owner.
SHARED_PLATFORMS = {"github.io", "githubusercontent.com", "blogspot.com", "weebly.com", "wixsite.com", "web.app", "firebaseapp.com",
    "netlify.app", "pages.dev", "vercel.app", "herokuapp.com", "glitch.me", "notion.site", "000webhostapp.com", "appspot.com",
    "azurewebsites.net", "amazonaws.com", "forms.gle", "sharepoint.com", "dropboxusercontent.com", "dropbox.com", "wordpress.com",
    "myshopify.com", "typeform.com", "googlegroups.com", "ripway.com", "repl.co", "weebly.com", "godaddysites.com", "carrd.co"}
GOOGLE_USER_CONTENT = {"docs", "sites", "drive", "forms", "script", "storage", "groups", "sheets", "spreadsheets", "slides", "firebase"}
SUSPICIOUS_WORDS = {"verify": "verification wording", "password": "mentions a password", "credential": "mentions credentials", "wallet": "mentions a wallet",
    "signin": "sign-in wording", "login": "login wording", "update": "account-update wording", "secure": "uses 'secure' (not proof of safety)",
    "banking": "mentions banking", "confirm": "asks for confirmation", "kyc": "KYC wording (common in Indian bank scams)", "suspend": "account-suspension wording",
    "urgent": "urgency wording", "prize": "prize/reward wording", "gift": "gift/reward wording", "free": "'free' offer wording", "otp": "mentions OTP", "refund": "refund wording"}

def load():
    global _B
    if _B is None:
        p = os.path.join(BASE, "fraudshield_v2.pkl")
        if not os.path.exists(p): raise RuntimeError("Model file missing. Run: python train_v2.py")
        _B = joblib.load(p)
    return _B

def model_probability(url, bundle=None):
    b = bundle or load(); f, info = extract(url)
    p_lr = float(b["lr"].predict_proba(b["tfidf"].transform(_HV.transform([text_for_ngrams(url)])))[0, 1])
    x = np.array([f + [p_lr]], dtype=np.float32)
    return float(b["hgb"].predict_proba(x)[0, 1]), p_lr, f, info

def _shared_platform(host, regdomain):
    if regdomain == "google.com":
        sub = host[: -len(regdomain)].rstrip(".").split(".")[0] if host != regdomain else ""
        return sub in GOOGLE_USER_CONTENT
    if regdomain in SHARED_PLATFORMS: return host not in (regdomain, "www." + regdomain) or regdomain in {"dropbox.com", "dropboxusercontent.com", "github.io"}
    return False

def analyze_url(raw_url, bundle=None):
    b = bundle or load(); p, p_lr, f, info = model_probability(raw_url, b)
    host, reg = info["host"], info["regdomain"]; ind = []; strong = 0
    def add(n, sev, d): ind.append({"indicator": n, "severity": sev, "details": d})
    if info["scheme"] != "https": add("No HTTPS", "low", "Not using HTTPS. Many phishing sites now use HTTPS, so this is informational and does not change the score.")
    if info["is_ip"]: add("IP address used as host", "high", "Raw IP address instead of a normal domain."); strong += 1
    if "@" in info["url"].split("//", 1)[-1].split("/", 1)[0]: add("At-sign in authority", "high", "An @ can hide the real destination."); strong += 1
    if host.startswith("xn--") or ".xn--" in host: add("Punycode hostname", "high", "Internationalised encoding is used in look-alike domains."); strong += 1
    brand_flag = info["brand_unofficial"] and not info["is_official"]
    if brand_flag:
        why = "uses look-alike characters" if info["brand_leet"] else "contains or closely resembles the brand name"
        add("Possible brand impersonation", "high", f"The domain {why} '{info['brand']}' but is not an official '{info['brand']}' domain ({reg}).")
    if host in SHORTENERS: add("URL shortener", "medium", "The real destination is hidden. Expand the link before trusting it.")
    shared = _shared_platform(host, reg)
    if shared: add("Shared hosting platform", "medium", f"{reg} lets anyone publish pages. Judge the page owner, not the platform name.")
    if len(info["url"]) > 120: add("Very long URL", "low", f"{len(info['url'])} characters.")
    if len([x for x in host.split(".") if x]) >= 5: add("Many hostname levels", "low", "Deeply nested subdomains are sometimes used to hide the real domain.")
    for w in info["words"][:5]:
        if w in SUSPICIOUS_WORDS: add("Keyword: " + w, "low", SUSPICIOUS_WORDS[w] + ". Informational only; legitimate pages use these words too.")
    risk = p
    if strong: risk = max(risk, 0.85)
    if brand_flag: risk = max(risk, 0.80)
    if host in SHORTENERS: risk = max(risk, 0.55)
    official_host = info["is_official"] and not shared and not strong
    if official_host:
        risk = min(risk, 0.12); add("Recognised official domain", "info", f"{reg} is on the official-domain list. This is not a live reputation check.")
    score = int(round(risk * 100)); tm, th = int(round(b["t_medium"] * 100)), int(round(b["t_high"] * 100))
    if score >= th: verdict, level, expl = "Suspicious", "High", "The model and/or URL indicators strongly suggest this link is malicious."
    elif score >= tm: verdict, level, expl = "Suspicious", "Medium", "Some warning signs were found. Verify the real domain before opening it."
    else: verdict, level, expl = "Likely Legitimate", "Low", "No strong warning signs were found, but this is not a guarantee of safety."
    if not ind: add("No obvious structural warning signs", "info", "Automated checks found nothing unusual.")
    return {"url": info["url"], "verdict": verdict, "risk_level": level, "risk_score": score, "ml_phishing_probability": round(p, 4),
            "char_ngram_probability": round(p_lr, 4), "hostname": host, "registered_domain": reg, "indicators": ind, "explanation": expl,
            "thresholds": {"medium": tm, "high": th},
            "disclaimer": "ML-based screening, not a live reputation service. Do not enter passwords or payment details based only on this result."}
