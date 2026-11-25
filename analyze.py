"""Turn the raw CSV files into the manuscript tables (Section 6) and figures.

Usage:  python analyze.py results        (or results_quick)
Needs:  pip install pandas numpy scipy matplotlib
Writes: <folder>/tables.md, <folder>/table_*.csv, <folder>/fig_*.png
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import mannwhitneyu

MB = 1024 * 1024
NAMES = {
    ("ascon", "on"): "Ascon-AEAD128 (proposed)",
    ("aes128gcm", "on"): "AES-128-GCM, AES-NI on",
    ("aes128gcm", "off"): "AES-128-GCM, AES-NI off",
    ("chacha20poly1305", "on"): "ChaCha20-Poly1305",
    ("aes256cbc", "on"): "AES-256-CBC, AES-NI on",
    ("aes256cbc", "off"): "AES-256-CBC, AES-NI off",
    ("3des", "on"): "3DES-CBC",
    ("blowfish", "on"): "Blowfish-CBC",
}
ORDER = list(NAMES.values())
SIZE_LABEL = {1024: "1 KB", 65536: "64 KB", MB: "1 MB", 10 * MB: "10 MB", 100 * MB: "100 MB", 500 * MB: "500 MB"}
rng = np.random.default_rng(12345)


def boot_ci(x, n=10000):
    x = np.asarray(x, dtype=float)
    if len(x) < 3:
        return (np.nan, np.nan)
    meds = np.median(rng.choice(x, size=(n, len(x)), replace=True), axis=1)
    return tuple(np.percentile(meds, [2.5, 97.5]))


def label(df):
    df = df.copy()
    df["config"] = [NAMES.get((s, a), f"{s} ({a})") for s, a in zip(df.scheme, df.aesni)]
    return df


def md_table(df, floatfmt="{:.3g}"):
    cols = list(df.columns)
    lines = ["| " + " | ".join(map(str, cols)) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for _, r in df.iterrows():
        cells = []
        for v in r:
            if isinstance(v, float):
                cells.append("—" if np.isnan(v) else floatfmt.format(v))
            else:
                cells.append(str(v))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main(folder):
    d = Path(folder)
    out = []
    n_note = []

    # ---------------- speed
    sp = label(pd.read_csv(d / "speed.csv"))
    sp["ms"] = sp.time_ns / 1e6
    sp["MBps"] = sp.size_bytes / MB / (sp.time_ns / 1e9)
    for op, title in (("encrypt", "Table 6.1 — Median encryption time (ms)"),
                      ("decrypt", "Table 6.2 — Median decryption time (ms)")):
        t = sp[sp.op == op].pivot_table(index="config", columns="size_bytes", values="ms", aggfunc="median")
        t = t.reindex([c for c in ORDER if c in t.index])
        t.columns = [SIZE_LABEL.get(c, c) for c in t.columns]
        t.to_csv(d / f"table_{op}_time_ms.csv")
        out += [f"## {title}", md_table(t.reset_index().rename(columns={"config": "Scheme"}), "{:.4g}"), ""]
    runs = sp.groupby(["size_bytes"]).run.nunique()
    n_note.append("Runs per size: " + ", ".join(f"{SIZE_LABEL.get(k, k)} = {v}" for k, v in runs.items()))

    # throughput at the largest size tested up to 100 MB
    big = 100 * MB if (sp.size_bytes == 100 * MB).any() else sp.size_bytes.max()
    s100 = sp[sp.size_bytes == big]
    asc = s100[(s100.config == NAMES[("ascon", "on")]) & (s100.op == "encrypt")]
    rows = []
    for cfg in [c for c in ORDER if c in set(s100.config)]:
        e = s100[(s100.config == cfg) & (s100.op == "encrypt")]
        dd = s100[(s100.config == cfg) & (s100.op == "decrypt")]
        lo, hi = boot_ci(e.MBps)
        p = np.nan
        if cfg != NAMES[("ascon", "on")] and len(e) >= 3 and len(asc) >= 3:
            p = mannwhitneyu(asc.time_ns, e.time_ns, alternative="two-sided").pvalue
        rows.append({"Scheme": cfg, "Encrypt MB/s": e.MBps.median(), "95% CI": f"{lo:.1f}–{hi:.1f}",
                     "Decrypt MB/s": dd.MBps.median(),
                     "Ascon / scheme (encrypt)": asc.MBps.median() / e.MBps.median(),
                     "Mann–Whitney p vs Ascon": p})
    t3 = pd.DataFrame(rows)
    t3.to_csv(d / "table_throughput.csv", index=False)
    out += [f"## Table 6.3 — Median throughput, {SIZE_LABEL.get(big, big)} file",
            md_table(t3, "{:.4g}"),
            "Ratio > 1 means Ascon is faster than that scheme; < 1 means slower.", ""]

    # ---------------- key setup, expansion, memory
    ks = label(pd.read_csv(d / "keysetup.csv"))
    rows = []
    e2e = label(pd.read_csv(d / "e2e.csv")) if (d / "e2e.csv").exists() else None
    for cfg in [c for c in ORDER if c in set(ks.config)]:
        k = ks[ks.config == cfg].iloc[-1]
        mem = np.nan
        if e2e is not None:
            m = e2e[(e2e.config == cfg) & (e2e.op == "encrypt")]
            if len(m):
                mem = m[m.size_bytes == m.size_bytes.max()].peak_mem_mb.median()
        rows.append({"Scheme": cfg, "Peak memory, streaming encrypt (MB)": mem,
                     "Ciphertext expansion (%)": k.expansion_pct, "Key setup (µs)": k.keysetup_ns_per_file / 1000})
    t4 = pd.DataFrame(rows)
    t4.to_csv(d / "table_resources.csv", index=False)
    out += ["## Table 6.4 — Memory, expansion and key setup", md_table(t4, "{:.4g}"),
            "Peak memory is the whole process (program, OpenSSL and buffers) while streaming the largest "
            "end-to-end file. Key setup = header digest + key derivation + cipher key schedule. "
            "AES-NI-off rows have no streaming memory figure because the end-to-end test runs with default settings.", ""]

    # ---------------- chunk size
    ch = pd.read_csv(d / "chunk.csv")
    ch["MBps"] = ch.size_bytes / MB / (ch.time_ns / 1e9)
    rows = []
    for B, g in ch[ch.op == "encrypt"].groupby("chunk_bytes"):
        L = g.size_bytes.iloc[0]
        n = -(-L // B)
        rows.append({"Chunk size": f"{B // 1024} KiB", "Encrypt MB/s": g.MBps.median(),
                     "Decrypt MB/s": ch[(ch.op == "decrypt") & (ch.chunk_bytes == B)].MBps.median(),
                     "Expansion (%)": 100 * (66 + 8 + 16 * n) / L})
    t5 = pd.DataFrame(rows)
    t5.to_csv(d / "table_chunk.csv", index=False)
    out += ["## Table 6.5 — Ascon throughput versus chunk size (100 MB)", md_table(t5, "{:.4g}"),
            "Expansion computed from the format (66-byte fixed header + 8-byte file name + 16-byte tag per chunk).", ""]

    # ---------------- avalanche
    av = pd.read_csv(d / "avalanche.csv")
    av["Scheme"] = [NAMES[(s, "on")] for s in av.scheme]
    t6 = av.pivot_table(index=["Scheme", "region"], columns="flip", values="mean_pct").reset_index()
    t6.to_csv(d / "table_avalanche.csv", index=False)
    out += ["## Table 6.6 — Avalanche effect (% of output bits changed, ideal 50%)", md_table(t6, "{:.2f}"),
            "1 KB inputs, same nonce/IV for both encryptions (measurement only).", ""]

    # ---------------- end to end
    if e2e is not None:
        e2e["s"] = e2e.time_ns / 1e9
        t7 = e2e.pivot_table(index="config", columns=["size_bytes", "op"], values="s", aggfunc="median")
        t7 = t7.reindex([c for c in ORDER if c in t7.index])
        t7 = t7[sorted(t7.columns, key=lambda c: (c[0], c[1] != "encrypt"))]
        t7.columns = [f"{SIZE_LABEL.get(sz, round(sz / MB))} {op} (s)" for sz, op in t7.columns]
        t7.to_csv(d / "table_e2e.csv")
        out += ["## Table 6.7 — End-to-end time from disk (median seconds)",
                md_table(t7.reset_index().rename(columns={"config": "Scheme"}), "{:.3f}"),
                "Includes reading the input file, encryption or decryption, and writing the output file.", ""]

    # ---------------- figures
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        enc = sp[sp.op == "encrypt"].groupby(["config", "size_bytes"]).ms.median().reset_index()
        fig, ax = plt.subplots(figsize=(7, 4.5))
        markers = "osD^v<>p"
        for i, cfg in enumerate([c for c in ORDER if c in set(enc.config)]):
            g = enc[enc.config == cfg]
            ax.plot(g.size_bytes / MB, g.ms, marker=markers[i % 8], label=cfg, lw=1.5)
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("File size (MB, log scale)"); ax.set_ylabel("Median encryption time (ms, log scale)")
        ax.grid(True, which="both", alpha=0.3); ax.legend(fontsize=8)
        fig.tight_layout(); fig.savefig(d / "fig_encrypt_time.png", dpi=300); plt.close(fig)

        fig, ax = plt.subplots(figsize=(7, 4))
        t3s = t3.sort_values("Encrypt MB/s")
        ax.barh(t3s.Scheme, t3s["Encrypt MB/s"], color=["#c0392b" if "Ascon" in s else "#7f8c8d" for s in t3s.Scheme])
        ax.set_xscale("log"); ax.set_xlabel(f"Median encryption throughput, {SIZE_LABEL.get(big, big)} (MB/s, log scale)")
        ax.grid(True, axis="x", which="both", alpha=0.3)
        fig.tight_layout(); fig.savefig(d / "fig_throughput.png", dpi=300); plt.close(fig)
    except ImportError:
        out.append("(matplotlib not installed: figures skipped)")

    head = [f"# Results from {d.name}", ""] + [f"- {x}" for x in n_note] + [
        "- Medians reported; 95% CI = bootstrap of the median (10,000 resamples).", ""]
    (d / "tables.md").write_text("\n".join(head + out), encoding="utf-8")
    print("\n".join(head + out))
    print(f"\nWrote {d / 'tables.md'} and figures in {d}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results")
