"""FraudShield v2 training + honest evaluation.
Split: GROUPED BY REGISTERED DOMAIN (no domain appears in both train and test): 70% train / 10% validation / 20% test.
Model: stack = char n-gram TF-IDF + LogisticRegression (out-of-fold probability) + handcrafted lexical/brand features -> HistGradientBoosting.
Baselines on the SAME split: P5-style (TF-IDF+LR), v1-style (TF-IDF+LR with scheme), P1/P2-style (Random Forest on lexical features)."""
import os, sys, json, time, re
import numpy as np, pandas as pd, joblib, scipy.sparse as sp
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit, GroupKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from features import extract, FEATURE_NAMES, text_for_ngrams, _ext
BASE = os.path.dirname(os.path.abspath(__file__)); T0 = time.time()
def log(*a): print(f"[{time.time()-T0:6.0f}s]", *a, flush=True)

df = pd.read_csv(os.path.join(BASE, "url_dataset.csv"))
df = df.dropna(subset=["label", "url"]).drop_duplicates(subset=["url"]).reset_index(drop=True)
df["label"] = df["label"].astype(str).str.lower().str.strip(); df = df[df.label.isin(["phishing", "legitimate"])].reset_index(drop=True)
df["url"] = df.url.astype(str).str.strip(); y = (df.label == "phishing").astype(int).values
log("rows", len(df))
feats, infos_reg, keep = [], [], []
for i, u in enumerate(df.url):
    try: f, inf = extract(u); feats.append(f); infos_reg.append(inf["regdomain"]); keep.append(i)
    except Exception: pass
df = df.iloc[keep].reset_index(drop=True); y = y[keep]; F = np.array(feats, dtype=np.float32); groups = np.array(infos_reg)
log("features", F.shape)

# ---- grouped splits
gs = GroupShuffleSplit(1, test_size=0.2, random_state=42); tr_all, te = next(gs.split(F, y, groups))
gs2 = GroupShuffleSplit(1, test_size=0.125, random_state=7); a, b = next(gs2.split(F[tr_all], y[tr_all], groups[tr_all]))
tr, va = tr_all[a], tr_all[b]
log("train/val/test", len(tr), len(va), len(te), "| domain overlap train-test:", len(set(groups[tr]) & set(groups[te])))

hv = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2**19, alternate_sign=False, norm=None, dtype=np.float32)
def hashed(texts): return sp.vstack([hv.transform(texts[i:i+20000]) for i in range(0, len(texts), 20000)]).tocsr()
txt = [text_for_ngrams(u) for u in df.url]; X = hashed(txt); log("hashed", X.shape)
def fit_lr(Xa, ya):
    tf = TfidfTransformer(sublinear_tf=True); A = tf.fit_transform(Xa)
    return tf, LogisticRegression(max_iter=300, class_weight="balanced", C=2.0, solver="liblinear").fit(A, ya)
def pred_lr(tf, lr, Xb): return lr.predict_proba(tf.transform(Xb))[:, 1]
# out-of-fold LR probabilities on train (grouped), full-train LR for val/test
oof = np.zeros(len(tr))
for k, (i1, i2) in enumerate(GroupKFold(4).split(tr, y[tr], groups[tr])):
    tf, lr = fit_lr(X[tr[i1]], y[tr[i1]]); oof[i2] = pred_lr(tf, lr, X[tr[i2]]); log("oof fold", k)
tf_full, lr_full = fit_lr(X[tr], y[tr]); p_lr_va = pred_lr(tf_full, lr_full, X[va]); p_lr_te = pred_lr(tf_full, lr_full, X[te]); log("LR full done")

def stackX(Fm, p): return np.hstack([Fm, p.reshape(-1, 1)])
hgb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, max_leaf_nodes=48, l2_regularization=1.0, random_state=42)
hgb.fit(stackX(F[tr], oof), y[tr]); p_st_va = hgb.predict_proba(stackX(F[va], p_lr_va))[:, 1]; p_st_te = hgb.predict_proba(stackX(F[te], p_lr_te))[:, 1]; log("stack done")
hgb_f = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, max_leaf_nodes=48, l2_regularization=1.0, random_state=42).fit(F[tr], y[tr])
p_hgbf_te = hgb_f.predict_proba(F[te])[:, 1]
rf = RandomForestClassifier(n_estimators=120, min_samples_leaf=2, n_jobs=1, random_state=42).fit(F[tr], y[tr]); p_rf_te = rf.predict_proba(F[te])[:, 1]; log("RF done")
# v1-style baseline (scheme kept)
Xs = hashed([u.lower() for u in df.url.iloc[np.concatenate([tr, te])]]); ntr = len(tr)
tf1, lr1 = fit_lr(Xs[:ntr], y[tr]); p_v1_te = pred_lr(tf1, lr1, Xs[ntr:]); del Xs; log("v1-style done")

def met(yt, p, thr=0.5):
    pr = (p >= thr).astype(int); cm = confusion_matrix(yt, pr)
    return dict(acc=accuracy_score(yt, pr), prec=precision_score(yt, pr), rec=recall_score(yt, pr), f1=f1_score(yt, pr),
                fpr=cm[0, 1] / cm[0].sum(), fnr=cm[1, 0] / cm[1].sum(), auc=roc_auc_score(yt, p), cm=cm.tolist())
yte = y[te]; res = {}
res["v1_style_tfidf_lr_with_scheme"] = met(yte, p_v1_te)
res["P5_style_tfidf_lr_no_scheme"] = met(yte, p_lr_te)
res["P1P2_style_random_forest_lexical"] = met(yte, p_rf_te)
res["hist_gradient_boosting_lexical_only"] = met(yte, p_hgbf_te)
res["v2_stack_at_0.5"] = met(yte, p_st_te)
# thresholds from VALIDATION: t_med minimises FNR + 5*FPR (cost used in P3), t_high gives FPR <= 0.5%
ths = np.linspace(0.02, 0.98, 193); yv = y[va]
def rates(p, yy, t): pr = p >= t; return (pr[yy == 0].mean(), 1 - pr[yy == 1].mean())
cost = [rates(p_st_va, yv, t)[1] + 5 * rates(p_st_va, yv, t)[0] for t in ths]; t_med = float(ths[int(np.argmin(cost))])
t_high = float(next((t for t in ths if rates(p_st_va, yv, t)[0] <= 0.005), 0.9)); t_high = max(t_high, t_med)
res["thresholds_from_validation"] = dict(t_medium=t_med, t_high=t_high)
res["v2_stack_at_t_medium"] = met(yte, p_st_te, t_med); res["v2_stack_at_t_high"] = met(yte, p_st_te, t_high)
# bootstrap CI (stack, t_medium)
rs = np.random.RandomState(0); pr = (p_st_te >= t_med).astype(int); accs = []
for _ in range(1000):
    ix = rs.randint(0, len(yte), len(yte)); accs.append((pr[ix] == yte[ix]).mean())
res["v2_stack_acc_95CI"] = [float(np.percentile(accs, 2.5)), float(np.percentile(accs, 97.5))]
# login-URL subset (hard case in P5)
lg = df.url.iloc[te].str.lower().str.contains("login|signin|sign-in|log-in").values
sub = {}
for nm, p in [("v1_style", p_v1_te), ("P5_style", p_lr_te), ("RF_lexical", p_rf_te), ("v2_stack", p_st_te)]:
    thr = t_med if nm == "v2_stack" else 0.5
    pr_ = p >= thr; sub[nm] = dict(n_legit_login=int(((yte == 0) & lg).sum()), fpr_on_legit_login=float(pr_[(yte == 0) & lg].mean()),
                                    n_phish_login=int(((yte == 1) & lg).sum()), recall_on_phish_login=float(pr_[(yte == 1) & lg].mean()))
res["login_url_subset"] = sub
imp = hgb_f.__dict__.get("feature_importances_", None)
res["meta"] = dict(rows=len(df), train=len(tr), val=len(va), test=len(te), split="grouped by registered domain; no domain overlap", seconds=time.time() - T0)
json.dump(res, open(os.path.join(BASE, "evaluation_results_v2.json"), "w"), indent=2)
np.savez(os.path.join(BASE, "_test_preds.npz"), te=te, yte=yte, p_st=p_st_te, p_lr=p_lr_te)
# ---- final artifacts: refit on train+val for deployment (thresholds kept from validation)
tv = np.concatenate([tr, va]); oof2 = np.zeros(len(tv))
for k, (i1, i2) in enumerate(GroupKFold(4).split(tv, y[tv], groups[tv])):
    t_, l_ = fit_lr(X[tv[i1]], y[tv[i1]]); oof2[i2] = pred_lr(t_, l_, X[tv[i2]])
tf_d, lr_d = fit_lr(X[tv], y[tv]); hgb_d = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, max_leaf_nodes=48, l2_regularization=1.0, random_state=42).fit(stackX(F[tv], oof2), y[tv])
joblib.dump(dict(tfidf=tf_d, lr=lr_d, hgb=hgb_d, feature_names=FEATURE_NAMES, t_medium=t_med, t_high=t_high, n_features=2**19), os.path.join(BASE, "fraudshield_v2.pkl"), compress=3)
log("saved model"); print(json.dumps(res, indent=1))
