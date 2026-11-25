# ascon-file-bench

Code for the manuscript *Lightweight Authenticated File Encryption Using the NIST Ascon Standard (SP 800-232)*.

It contains:
- the proposed chunked file format (Ascon-AEAD128 + Ascon-CXOF128 + Ascon-Hash256),
- the same format with AES-128-GCM and ChaCha20-Poly1305 (SHA-256 + HKDF-SHA256 for header and key), so only the primitives differ,
- AES-256-CBC, 3DES-CBC and Blowfish-CBC baselines (no integrity, as deployed in legacy tools),
- every experiment in Section 6, and a script that turns the raw CSVs into the manuscript tables and figures.

Ascon code: official `ascon-c` reference repository (CC0), bundled in `third_party/` with its commit hash in `SOURCE.txt`.

## 1. One-time setup on Windows (about 15 minutes)

1. Install MSYS2 from https://www.msys2.org (default options).
2. Open **"MSYS2 UCRT64"** from the Start menu (not "MSYS2 MSYS").
3. Install the compiler, OpenSSL and Python packages:

```bash
pacman -Syu        # if the window closes, reopen "MSYS2 UCRT64" and run it again
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-python mingw-w64-ucrt-x86_64-python-pandas \
  mingw-w64-ucrt-x86_64-python-scipy mingw-w64-ucrt-x86_64-python-matplotlib
```

4. Unzip this folder, e.g. to `C:\Users\<you>\ascon-file-bench`, then in the UCRT64 window:

```bash
cd /c/Users/<you>/ascon-file-bench
./build.sh
./build/bench selftest
```

`selftest` must print PASS for the three known-answer tests and all six round trips.

## 2. Run the experiments

```bash
python run_all.py --quick     # ~2 minutes; checks everything works. Do NOT use these numbers.
python run_all.py             # full run, roughly 45-60 minutes
python analyze.py results     # writes results/tables.md, table_*.csv, fig_*.png
```

Before the full run: charger connected, Windows power mode set to "Best performance", other programs closed (including the browser), laptop idle for a few minutes. Do not use the laptop while it runs. The benchmark pins itself to CPU core 2; change with `export BENCH_CORE=4`.

Disk use: the end-to-end test needs about 2 GB free at a time and deletes its files afterwards.

## 3. What each output file means

| File | Manuscript use |
| --- | --- |
| `system.txt` | Table 5.1 (CPU, OS, OpenSSL and compiler versions) |
| `selftest.txt` | State in Section 5.5 that KATs and round trips passed |
| `tamper.txt` | Section 7.2: experimental confirmation of each attack defence |
| `speed.csv` → Tables 6.1–6.3, `fig_encrypt_time.png`, `fig_throughput.png` | Time and throughput, 1 KB–500 MB |
| `keysetup.csv`, `e2e.csv` → Table 6.4 | Key setup, ciphertext expansion, peak memory |
| `chunk.csv` → Table 6.5 | Chunk-size sweep (4 KiB–1 MiB) |
| `avalanche.csv` → Table 6.6 | Plaintext- and key-bit avalanche |
| `e2e.csv` → Table 6.7 | Read + encrypt + write time from disk, 100 MB and 500 MB |

## 4. Method notes for the paper

- AES-NI is switched off with `OPENSSL_ia32cap=~0x200000200000000`. In testing this mask also slowed ChaCha20-Poly1305, so the AES-NI-off condition is run for the two AES schemes only.
- Small sizes (below 8 MB) repeat the operation enough times to give a measurable interval and report time per operation (column `reps`).
- Every run order is rotated across schemes to spread thermal and frequency drift; 3 warm-up runs are discarded.
- Every decryption is compared byte-for-byte with the plaintext; any mismatch stops the program.
- Statistics: medians, bootstrap 95% CI of the median, Mann–Whitney U test against Ascon.
- `encfile`/`decfile` use a fixed all-zero demo master key. Replace it with a key store or Argon2id before any real use.

## Troubleshooting

- `legacy provider (needed for Blowfish) not found`: run `export OPENSSL_MODULES=/ucrt64/lib/ossl-modules` and retry.
- `wmic` errors in `system.txt` on newer Windows 11: copy CPU and OS details from Settings → System → About by hand.
- Use the reference Ascon implementation instead of opt64: `ASCON_IMPL=ref ./build.sh`.

## Results in this repository

`results/` holds the raw output of the full run reported in the manuscript: AMD Ryzen 5 5600H laptop,
Windows 11 (build 26100), OpenSSL 3.5.9, on battery power, 25 November 2026. Regenerate every table and figure with
`python analyze.py results`. `paper/references.bib` holds the verified references for the manuscript.
