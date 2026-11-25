# Results from results

- Runs per size: 1 KB = 30, 64 KB = 30, 1 MB = 30, 10 MB = 30, 100 MB = 30, 500 MB = 10
- Medians reported; 95% CI = bootstrap of the median (10,000 resamples).

## Table 6.1 — Median encryption time (ms)
| Scheme | 1 KB | 64 KB | 1 MB | 10 MB | 100 MB | 500 MB |
| --- | --- | --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 0.006109 | 0.189 | 2.981 | 29.78 | 303.6 | 1582 |
| AES-128-GCM, AES-NI on | 0.00683 | 0.02312 | 0.282 | 2.737 | 27.77 | 144.2 |
| AES-128-GCM, AES-NI off | 0.01382 | 0.2489 | 3.821 | 38.48 | 386.9 | 1926 |
| ChaCha20-Poly1305 | 0.007357 | 0.03885 | 0.529 | 5.183 | 52.04 | 263.5 |
| AES-256-CBC, AES-NI on | 0.007902 | 0.08612 | 1.27 | 12.65 | 126.3 | 630.6 |
| AES-256-CBC, AES-NI off | 0.01488 | 0.305 | 4.705 | 46.87 | 469.5 | 2349 |
| 3DES-CBC | 0.04717 | 2.49 | 39.67 | 395.7 | 3981 | 1.999e+04 |
| Blowfish-CBC | 0.04463 | 0.5102 | 7.582 | 75.68 | 759.6 | 3807 |

## Table 6.2 — Median decryption time (ms)
| Scheme | 1 KB | 64 KB | 1 MB | 10 MB | 100 MB | 500 MB |
| --- | --- | --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 0.005083 | 0.1762 | 2.784 | 27.96 | 284.3 | 1441 |
| AES-128-GCM, AES-NI on | 0.005927 | 0.02176 | 0.2724 | 2.71 | 27.6 | 138.7 |
| AES-128-GCM, AES-NI off | 0.01161 | 0.2475 | 3.841 | 38.17 | 386.1 | 1938 |
| ChaCha20-Poly1305 | 0.006269 | 0.03752 | 0.5207 | 5.175 | 52.01 | 260.6 |
| AES-256-CBC, AES-NI on | 0.005665 | 0.01623 | 0.1847 | 1.899 | 19.78 | 99.44 |
| AES-256-CBC, AES-NI off | 0.01012 | 0.1757 | 2.694 | 26.74 | 271.2 | 1348 |
| 3DES-CBC | 0.04456 | 2.444 | 38.95 | 390.2 | 3921 | 2.001e+04 |
| Blowfish-CBC | 0.04253 | 0.4588 | 6.799 | 67.74 | 685 | 3458 |

## Table 6.3 — Median throughput, 100 MB file
| Scheme | Encrypt MB/s | 95% CI | Decrypt MB/s | Ascon / scheme (encrypt) | Mann–Whitney p vs Ascon |
| --- | --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 329.4 | 327.3–331.7 | 351.7 | 1 | — |
| AES-128-GCM, AES-NI on | 3600 | 3555.5–3615.9 | 3623 | 0.0915 | 3.02e-11 |
| AES-128-GCM, AES-NI off | 258.5 | 256.6–260.2 | 259 | 1.274 | 3.02e-11 |
| ChaCha20-Poly1305 | 1922 | 1909.7–1928.3 | 1923 | 0.1714 | 3.02e-11 |
| AES-256-CBC, AES-NI on | 791.9 | 789.0–793.9 | 5056 | 0.416 | 3.02e-11 |
| AES-256-CBC, AES-NI off | 213 | 212.3–213.2 | 368.8 | 1.547 | 3.02e-11 |
| 3DES-CBC | 25.12 | 24.9–25.2 | 25.5 | 13.12 | 3.02e-11 |
| Blowfish-CBC | 131.7 | 131.4–132.3 | 146 | 2.502 | 3.02e-11 |
Ratio > 1 means Ascon is faster than that scheme; < 1 means slower.

## Table 6.4 — Memory, expansion and key setup
| Scheme | Peak memory, streaming encrypt (MB) | Ciphertext expansion (%) | Key setup (µs) |
| --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 8.07 | 0.02448 | 2.87 |
| AES-128-GCM, AES-NI on | 8.28 | 0.02448 | 5.38 |
| AES-128-GCM, AES-NI off | — | 0.02448 | 7.619 |
| ChaCha20-Poly1305 | 8.28 | 0.02448 | 4.953 |
| AES-256-CBC, AES-NI on | 8.24 | 0.0001 | 5.003 |
| AES-256-CBC, AES-NI off | — | 0.0001 | 7.181 |
| 3DES-CBC | 8.26 | 9e-05 | 5.472 |
| Blowfish-CBC | 8.27 | 9e-05 | 35.08 |
Peak memory is the whole process (program, OpenSSL and buffers) while streaming the largest end-to-end file. Key setup = header digest + key derivation + cipher key schedule. AES-NI-off rows have no streaming memory figure because the end-to-end test runs with default settings.

## Table 6.5 — Ascon throughput versus chunk size (100 MB)
| Chunk size | Encrypt MB/s | Decrypt MB/s | Expansion (%) |
| --- | --- | --- | --- |
| 4 KiB | 323.1 | 344 | 0.3907 |
| 16 KiB | 328 | 349.8 | 0.09773 |
| 64 KiB | 333 | 354.1 | 0.02448 |
| 256 KiB | 333.4 | 352.1 | 0.006174 |
| 1024 KiB | 331.3 | 352.8 | 0.001596 |
Expansion computed from the format (66-byte fixed header + 8-byte file name + 16-byte tag per chunk).

## Table 6.6 — Avalanche effect (% of output bits changed, ideal 50%)
| Scheme | region | key | plaintext |
| --- | --- | --- | --- |
| 3DES-CBC | ciphertext | 50.00 | 25.53 |
| AES-128-GCM, AES-NI on | ciphertext+tag | 50.02 | 0.78 |
| AES-128-GCM, AES-NI on | tag_only | 50.09 | 49.94 |
| AES-256-CBC, AES-NI on | ciphertext | 49.99 | 26.01 |
| Ascon-AEAD128 (proposed) | ciphertext+tag | 50.02 | 25.11 |
| Ascon-AEAD128 (proposed) | tag_only | 50.09 | 50.17 |
| Blowfish-CBC | ciphertext | 49.98 | 25.02 |
| ChaCha20-Poly1305 | ciphertext+tag | 50.02 | 0.79 |
| ChaCha20-Poly1305 | tag_only | 49.85 | 50.23 |
1 KB inputs, same nonce/IV for both encryptions (measurement only).

## Table 6.7 — End-to-end time from disk (median seconds)
| Scheme | 100 MB encrypt (s) | 100 MB decrypt (s) | 500 MB encrypt (s) | 500 MB decrypt (s) |
| --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 0.414 | 0.377 | 2.781 | 2.019 |
| AES-128-GCM, AES-NI on | 0.138 | 0.138 | 1.892 | 0.643 |
| ChaCha20-Poly1305 | 0.155 | 0.141 | 2.195 | 1.051 |
| AES-256-CBC, AES-NI on | 0.244 | 0.133 | 2.042 | 0.710 |
| 3DES-CBC | 4.109 | 4.051 | 21.038 | 20.431 |
| Blowfish-CBC | 0.857 | 0.799 | 5.137 | 4.182 |
Includes reading the input file, encryption or decryption, and writing the output file.
