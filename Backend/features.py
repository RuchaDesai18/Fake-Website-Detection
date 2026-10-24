"""Shared URL feature extraction for FraudShield v2 (training and runtime use the SAME code).
The URL scheme (http/https) is deliberately NOT used as a feature: modern phishing mostly uses HTTPS."""
import math, re, ipaddress
from urllib.parse import urlparse
import tldextract
from rapidfuzz import fuzz, process

_ext = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# brand -> official registered domains (global + India focused)
BRANDS = {
    "paypal": ["paypal.com"], "google": ["google.com", "google.co.in", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"], "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
    "facebook": ["facebook.com", "fb.com"], "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"],
    "netflix": ["netflix.com"], "linkedin": ["linkedin.com"], "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"], "ebay": ["ebay.com", "ebay.in"], "twitter": ["twitter.com", "x.com"],
    "telegram": ["telegram.org"], "spotify": ["spotify.com"], "zoom": ["zoom.us"],
    "flipkart": ["flipkart.com"], "paytm": ["paytm.com"], "phonepe": ["phonepe.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com"], "hdfcbank": ["hdfcbank.com"], "icici": ["icicibank.com"], "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"], "kotak": ["kotak.com"], "yesbank": ["yesbank.in"],
    "irctc": ["irctc.co.in"], "uidai": ["uidai.gov.in"], "npci": ["npci.org.in"],
    "incometax": ["incometax.gov.in"], "indiapost": ["indiapost.gov.in"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "bankofamerica": ["bankofamerica.com"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"],
}
BRAND_NAMES = sorted(BRANDS)
OFFICIAL = {d for v in BRANDS.values() for d in v}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
              "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "lnkd.in"}
SUSP_WORDS = ["verify", "password", "credential", "wallet", "signin", "login", "update", "secure", "banking",
              "confirm", "recover", "gift", "prize", "free", "urgent", "suspend", "kyc", "account", "alert",
              "unlock", "limited", "billing", "invoice", "refund", "otp", "support"]
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "@": "a", "$": "s"})
FEATURE_NAMES = [
    "len_url", "len_host", "len_path", "len_query", "n_dots_host", "n_labels", "n_hyphens_host", "n_digits_host",
    "digit_ratio_url", "digit_ratio_host", "n_special", "has_at", "is_ip", "has_punycode", "entropy_url",
    "entropy_host", "longest_label", "tld_len", "n_path_segments", "has_port", "n_susp_words", "has_login_word",
    "is_shortener", "is_official", "brand_in_host_unofficial", "brand_leet_unofficial", "brand_sim_max",
    "domain_label_len", "domain_vowel_ratio", "max_digit_run", "has_hex_token", "n_subdomains", "n_query_params",
    "double_slash_path", "n_encoded", "path_has_ext_exe", "brand_in_path_unofficial",
]

def _entropy(s):
    if not s: return 0.0
    n = len(s); c = {}
    for ch in s: c[ch] = c.get(ch, 0) + 1
    return -sum(v / n * math.log2(v / n) for v in c.values())

def parse(raw):
    raw = str(raw).strip()
    if not raw: raise ValueError("URL is empty.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw): raw = "http://" + raw
    p = urlparse(raw)
    if not p.hostname: raise ValueError("That does not look like a valid URL. Enter a domain such as example.com.")
    return raw, p

def text_for_ngrams(raw):
    """URL string without scheme, lower-cased: input of the char n-gram model."""
    return re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", str(raw).strip()).lower()

def brand_info(host, reg_label, regdomain, path):
    """Return (brand_in_host_unofficial, brand_leet_unofficial, brand_sim_max, matched_brand, brand_in_path_unofficial)."""
    official = regdomain in OFFICIAL
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    leet_tokens = [t.translate(LEET) for t in tokens]
    in_host = leet = in_path = 0; matched = None
    if not official:
        for b in BRAND_NAMES:
            if b in tokens and len(b) >= 3: in_host = 1; matched = matched or b
            elif any(lt == b and t != b for t, lt in zip(tokens, leet_tokens)): leet = 1; matched = matched or b
        ptoks = [t for t in re.split(r"[^a-z0-9]+", path.lower()) if t]
        in_path = int(any(b in ptoks for b in BRAND_NAMES if len(b) >= 4))
    sim = 0.0
    if reg_label and not official:
        m = process.extractOne(reg_label.translate(LEET), BRAND_NAMES, scorer=fuzz.ratio)
        if m: sim = float(m[1]); 
        if m and m[1] >= 80 and not matched: matched = m[0]
    return in_host, leet, sim, matched, in_path

def extract(raw):
    """Return (feature list in FEATURE_NAMES order, info dict for explanations)."""
    url, p = parse(raw)
    host = (p.hostname or "").lower().rstrip("."); path = p.path or ""; query = p.query or ""
    try: ipaddress.ip_address(host); is_ip = 1
    except ValueError: is_ip = 0
    e = _ext(host)
    regdomain = (e.domain + "." + e.suffix) if e.suffix else host
    labels = [x for x in host.split(".") if x]
    low = url.lower(); body = low.split("://", 1)[-1]
    digits_url = sum(c.isdigit() for c in body); digits_host = sum(c.isdigit() for c in host)
    in_host, leet, sim, matched, in_path = brand_info(host, e.domain, regdomain, path)
    n_susp = sum(w in body for w in SUSP_WORDS)
    dl = e.domain or ""
    vowels = sum(c in "aeiou" for c in dl)
    runs = re.findall(r"\d+", body); max_run = max((len(r) for r in runs), default=0)
    f = [len(body), len(host), len(path), len(query), host.count("."), len(labels), host.count("-"), digits_host,
         digits_url / max(len(body), 1), digits_host / max(len(host), 1),
         sum(body.count(c) for c in "@?&=_%~"), int("@" in p.netloc), is_ip, int(host.startswith("xn--") or ".xn--" in host),
         _entropy(body), _entropy(host), max((len(x) for x in labels), default=0), len(e.suffix or ""),
         len([x for x in path.split("/") if x]), int(p.port is not None), n_susp,
         int(("login" in body) or ("signin" in body) or ("sign-in" in body) or ("log-in" in body)),
         int(host in SHORTENERS), int(regdomain in OFFICIAL), in_host, leet, sim, len(dl),
         vowels / max(len(dl), 1), max_run, int(bool(re.search(r"[0-9a-f]{16,}", body))), len(e.subdomain.split(".")) if e.subdomain else 0,
         len([q for q in query.split("&") if q]), int("//" in path), len(re.findall(r"%[0-9a-fA-F]{2}", body)),
         int(bool(re.search(r"\.(exe|apk|zip|scr|msi|bat)$", path.lower()))), in_path]
    info = dict(url=url, host=host, regdomain=regdomain, is_ip=bool(is_ip), brand=matched,
                brand_unofficial=bool(in_host or leet or sim >= 85), brand_leet=bool(leet), brand_sim=sim,
                words=[w for w in SUSP_WORDS if w in body], scheme=p.scheme.lower(), is_official=regdomain in OFFICIAL)
    return f, info
