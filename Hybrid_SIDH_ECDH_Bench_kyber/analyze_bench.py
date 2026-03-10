#!/usr/bin/env python3
# analyze_bench.py
# Usage:
#   python3 analyze_bench.py --hybrid results_hybrid.csv --normal results_normal.csv
#   (ou sans args : il essaie results_hybrid.csv / results_normal.csv dans le cwd)

import argparse, os, sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

STAGES = ["T_keygen_ms", "T_mask_ms", "T_tx_ms", "T_unmask_ms", "T_total_ms"]

def load_csv(path):
    df = pd.read_csv(path)
    for c in STAGES:
        if c not in df.columns: df[c] = np.nan
    if "iter" not in df.columns: df["iter"] = np.arange(1, len(df)+1)
    return df

def summarize(df, label):
    print(f"\n=== {label} ===")
    cols = ["mean","std","median","min","max","n"]
    rows = {}
    for c in STAGES:
        s = df[c].dropna()
        if len(s)==0: continue
        rows[c] = {
            "mean":   s.mean(),
            "std":    s.std(ddof=1),
            "median": s.median(),
            "min":    s.min(),
            "max":    s.max(),
            "n":      len(s),
        }
    if not rows:
        print("Aucune métrique trouvée.")
        return None
    tbl = pd.DataFrame(rows).T[cols]
    print(tbl.to_string(float_format=lambda x: f"{x:.3f}"))
    return tbl

def ensure_same_length(df_h, df_n):
    m = min(len(df_h), len(df_n))
    return df_h.iloc[:m].copy(), df_n.iloc[:m].copy()

def plot_time_series(df_h, df_n):
    plt.figure(figsize=(9,4.8))
    plt.plot(df_h["iter"], df_h["T_total_ms"], label="Hybrid T_total")
    plt.plot(df_n["iter"], df_n["T_total_ms"], label="Normal T_total")
    plt.xlabel("Iteration"); plt.ylabel("T_total (ms)")
    plt.title("Total time per iteration — Hybrid vs Normal")
    plt.legend(); plt.tight_layout()
    plt.savefig("01_total_time_overlay.png", dpi=160); plt.close()

def plot_stage_bars(df_h, df_n):
    means_h = []; stds_h = []; means_n = []; stds_n = []
    labels = []
    for c in ["T_keygen_ms","T_mask_ms","T_tx_ms","T_unmask_ms","T_total_ms"]:
        sh = df_h[c].dropna()
        sn = df_n[c].dropna()
        if len(sh)==0 and len(sn)==0: continue
        labels.append(c.replace("_ms","").replace("T_",""))
        means_h.append(sh.mean() if len(sh) else np.nan)
        stds_h.append(sh.std(ddof=1) if len(sh)>1 else 0.0)
        means_n.append(sn.mean() if len(sn) else np.nan)
        stds_n.append(sn.std(ddof=1) if len(sn)>1 else 0.0)

    x = np.arange(len(labels))
    w = 0.38
    plt.figure(figsize=(9,4.8))
    plt.bar(x - w/2, means_n, yerr=stds_n, width=w, label="Normal", capsize=3)
    plt.bar(x + w/2, means_h, yerr=stds_h, width=w, label="Hybrid", capsize=3)
    plt.xticks(x, labels)
    plt.ylabel("Time (ms)")
    plt.title("Mean ± std by stage — Normal vs Hybrid")
    plt.legend(); plt.tight_layout()
    plt.savefig("02_stage_bars.png", dpi=160); plt.close()

def plot_cdf(df_h, df_n):
    def cdf_values(series):
        s = np.sort(series.dropna().values)
        if len(s)==0: return None, None
        y = np.linspace(0,1,len(s))
        return s, y
    xh, yh = cdf_values(df_h["T_total_ms"])
    xn, yn = cdf_values(df_n["T_total_ms"])
    plt.figure(figsize=(9,4.8))
    if xh is not None: plt.plot(xh, yh, label="Hybrid T_total CDF")
    if xn is not None: plt.plot(xn, yn, label="Normal T_total CDF")
    plt.xlabel("T_total (ms)"); plt.ylabel("Cumulative probability")
    plt.title("CDF of T_total — Hybrid vs Normal")
    plt.grid(True, alpha=0.3)
    plt.legend(); plt.tight_layout()
    plt.savefig("03_cdf_total.png", dpi=160); plt.close()

def plot_hist_tx_mask(df_h, df_n):
    plt.figure(figsize=(9,4.8))
    # T_tx
    if df_h["T_tx_ms"].notna().any(): 
        plt.hist(df_h["T_tx_ms"].dropna(), bins=30, alpha=0.5, label="Hybrid T_tx")
    if df_n["T_tx_ms"].notna().any():
        plt.hist(df_n["T_tx_ms"].dropna(), bins=30, alpha=0.5, label="Normal T_tx")
    # T_mask (souvent ~0 côté normal)
    if df_h["T_mask_ms"].notna().any():
        plt.hist(df_h["T_mask_ms"].dropna(), bins=30, alpha=0.4, label="Hybrid T_mask")
    if df_n["T_mask_ms"].notna().any():
        plt.hist(df_n["T_mask_ms"].dropna(), bins=30, alpha=0.4, label="Normal T_mask")
    plt.xlabel("Time (ms)"); plt.ylabel("Count")
    plt.title("Distributions — T_tx and T_mask")
    plt.legend(); plt.tight_layout()
    plt.savefig("04_hist_tx_mask.png", dpi=160); plt.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hybrid", type=str, default="results_hybrid.csv")
    ap.add_argument("--normal", type=str, default="results_normal.csv")
    args = ap.parse_args()

    if not os.path.exists(args.hybrid) or not os.path.exists(args.normal):
        print("➡️  Fournis les deux fichiers CSV : --hybrid et --normal")
        print("    (ou place results_hybrid.csv et results_normal.csv dans le dossier courant)")
        sys.exit(1)

    df_h = load_csv(args.hybrid)
    df_n = load_csv(args.normal)

    # Tronquer à la même longueur pour des courbes comparables
    df_h, df_n = ensure_same_length(df_h, df_n)

    # Résumés + Overhead
    th = summarize(df_h, "Hybrid")
    tn = summarize(df_n, "Normal")
    if th is not None and tn is not None:
        h = df_h["T_total_ms"].dropna()
        n = df_n["T_total_ms"].dropna()
        if len(h)>0 and len(n)>0 and n.mean()>0:
            overhead = (h.mean() - n.mean())/n.mean()*100.0
            print(f"\nOverhead Hybrid vs Normal (mean T_total): {overhead:.2f}%")
        else:
            print("\nOverhead: données insuffisantes.")

    # Graphiques comparatifs
    plot_time_series(df_h, df_n)
    plot_stage_bars(df_h, df_n)
    plot_cdf(df_h, df_n)
    plot_hist_tx_mask(df_h, df_n)

    print("\nImages générées :")
    print("  01_total_time_overlay.png")
    print("  02_stage_bars.png")
    print("  03_cdf_total.png")
    print("  04_hist_tx_mask.png")

if __name__ == "__main__":
    main()
