# FraudShield URL Module v2

Drop-in upgrade of the v1 Backend. Same API (`POST /detect_url`) and same JSON fields, so the existing Frontend works unchanged.

## Run
1. Copy this `Backend` folder over your old one (keep `url_dataset.csv` in it; it is NOT included here).
2. `pip install -r requirements.txt`
3. (Recommended) `python train_v2.py` to rebuild `fraudshield_v2.pkl` for YOUR scikit-learn version (~6 min). The shipped pickle was built with scikit-learn 1.8.
4. `python app_v2.py`, then start the Frontend as before (port 8000; CORS now allows only that origin).
5. `python test_v2.py` for demo probes.

## What changed vs v1
| Area | v1 | v2 |
|---|---|---|
| Model | char 3-5-gram TF-IDF + LR | Stack: char n-gram LR (out-of-fold) + 37 lexical/brand features -> HistGradientBoosting |
| Scheme (http/https) | used by the model (dataset skew) | removed from all features |
| Brand impersonation | keyword "paypal" only | brand list (global + Indian banks), look-alike and leetspeak detection (paypa1, amaz0n) |
| Allow-list | whole domains incl. docs/sites.google.com | exact registered domains; shared platforms (Google Docs/Sites, github.io, Dropbox...) excluded |
| Keyword rules | raised score floor | informational only |
| Thresholds | hand-set | Medium >= 50 (balanced), High >= 85 (~99% precision), chosen on a validation split |
| Evaluation | random split | split grouped by registered domain (no domain in both train and test), 95% CI, baselines on the same split |
| CORS | `*` | local frontend only |

## Results (domain-disjoint test set, 67,696 URLs; see evaluation_results_v2.json)
| Model | Accuracy | Precision | Recall | FPR | AUC |
|---|---|---|---|---|---|
| v1 method (TF-IDF+LR, scheme kept) | 96.79% | 96.26% | 97.33% | 3.74% | 0.9953 |
| P5-style (TF-IDF+LR, no scheme) | 95.87% | 96.29% | 95.37% | 3.63% | 0.9929 |
| P1/P2-style Random Forest, lexical features | 88.80% | 90.77% | 86.25% | 8.68% | 0.9591 |
| **v2 stack, threshold 0.50** | **97.18%** | **97.44%** | **96.87%** | **2.52%** | **0.9965** |
| **v2 stack, threshold 0.85 (High tier)** | 96.19% | **99.14%** | 93.14% | **0.80%** | 0.9965 |

v2 accuracy 95% CI at the 0.85 threshold: 96.04% to 96.32%. Full runtime pipeline on 6,000+6,000 held-out URLs: 97.17% accuracy / 2.85% FPR (Suspicious, score >= 50); 96.35% accuracy / 99.19% precision / 0.77% FPR (High, score >= 85). Latency: ~3.4 ms per URL (feature extraction + both models, one CPU core).

## Honest limitations (do not hide these in your report)
- **Not 98-99%.** On this dataset the ceiling observed is about 97%. Papers reporting 98-99% use other (often small or pre-processed) data; the numbers are not comparable.
- **Legitimate login pages are still a weak spot:** false-positive rate on legitimate URLs containing "login/signin" is 12.3% at threshold 0.5 (7.3% at 0.85), n = 220. The training data has almost no legitimate login pages (0.63% vs 21.7% of phishing). Fixing this needs better data, not a better model.
- **Bare official domains** (e.g. google.com) get a high raw model score because the data has few root-only legitimate URLs; the exact-domain allow-list is what keeps them Low.
- Real Google Forms/Docs/Sites links are flagged (too many phishing pages live there); this is a deliberate trade-off.
- No time-based evaluation (dataset has no dates) and no content, DNS or certificate evidence. URL-only.
- Brand list is small (about 40 brands). Extend `BRANDS` in features.py.
- No short-URL expansion; no feedback/retraining loop.
