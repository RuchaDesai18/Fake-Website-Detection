"""Quick demo/regression probes for v2. Run: python test_v2.py"""
from detector_v2 import analyze_url
CASES = [("https://www.google.com", "Low"), ("https://www.irctc.co.in/nget/train-search", "Low"), ("https://en.wikipedia.org/wiki/Phishing", "Low"),
         ("https://sbi-kyc-update.in/login", "High"), ("https://paypa1.com/", "Medium+"), ("https://amaz0n-support.com/help", "High"),
         ("https://sites.google.com/view/sbi-netbanking-login", "High"), ("http://hdfc-netbanking.verify-account.top/", "High"), ("https://bit.ly/3xYzAbC", "High")]
for url, expect in CASES:
    r = analyze_url(url); print(f"{r['risk_score']:>3} {r['risk_level']:<6} (expected {expect:<7}) {url}")
