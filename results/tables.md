# Results from results

- Runs per size: 1 KB = 30, 64 KB = 30, 1 MB = 30, 10 MB = 30, 100 MB = 30, 500 MB = 10
- Medians reported; 95% CI = bootstrap of the median (10,000 resamples).

## Table 6.1 — Median encryption time (ms)
| Scheme | 1 KB | 64 KB | 1 MB | 10 MB | 100 MB | 500 MB |
| --- | --- | --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 0.0032 | 0.09395 | 1.48 | 15.3 | 150.4 | 778.1 |
| AES-128-GCM, AES-NI on | 0.004356 | 0.01678 | 0.211 | 2.34 | 22.4 | 115.9 |
| AES-128-GCM, AES-NI off | 0.009332 | 0.1873 | 2.959 | 29.39 | 316.6 | 1544 |
| ChaCha20-Poly1305 | 0.004606 | 0.02871 | 0.4032 | 4.091 | 40.4 | 204.3 |
| AES-256-CBC, AES-NI on | 0.005078 | 0.06467 | 0.9677 | 9.845 | 96.74 | 489.1 |
| AES-256-CBC, AES-NI off | 0.00998 | 0.2313 | 3.647 | 35.99 | 372.1 | 1828 |
| 3DES-CBC | 0.03392 | 1.876 | 29.79 | 309.5 | 3023 | 1.531e+04 |
| Blowfish-CBC | 0.03253 | 0.3851 | 5.763 | 59.62 | 577.2 | 3045 |

## Table 6.2 — Median decryption time (ms)
| Scheme | 1 KB | 64 KB | 1 MB | 10 MB | 100 MB | 500 MB |
| --- | --- | --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 0.002534 | 0.09106 | 1.44 | 14.91 | 147.2 | 769.2 |
| AES-128-GCM, AES-NI on | 0.003559 | 0.01567 | 0.2053 | 2.308 | 21.98 | 109.5 |
| AES-128-GCM, AES-NI off | 0.007581 | 0.1853 | 2.947 | 29.15 | 314.7 | 1523 |
| ChaCha20-Poly1305 | 0.003778 | 0.02753 | 0.3921 | 4.098 | 40.21 | 204.5 |
| AES-256-CBC, AES-NI on | 0.003235 | 0.01153 | 0.1388 | 1.863 | 19.43 | 108.2 |
| AES-256-CBC, AES-NI off | 0.006497 | 0.1328 | 2.074 | 20.6 | 219.6 | 1049 |
| 3DES-CBC | 0.03233 | 1.834 | 29.29 | 304.1 | 2983 | 1.538e+04 |
| Blowfish-CBC | 0.03075 | 0.3484 | 5.167 | 53.52 | 520.4 | 2661 |

## Table 6.3 — Median throughput, 100 MB file
| Scheme | Encrypt MB/s | 95% CI | Decrypt MB/s | Ascon / scheme (encrypt) | Mann–Whitney p vs Ascon |
| --- | --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 664.9 | 650.1–673.3 | 679.3 | 1 | — |
| AES-128-GCM, AES-NI on | 4465 | 4337.9–4562.2 | 4550 | 0.1489 | 3.02e-11 |
| AES-128-GCM, AES-NI off | 315.8 | 306.6–325.8 | 317.8 | 2.105 | 3.02e-11 |
| ChaCha20-Poly1305 | 2475 | 2432.0–2484.8 | 2487 | 0.2686 | 3.02e-11 |
| AES-256-CBC, AES-NI on | 1034 | 1029.8–1036.7 | 5147 | 0.6433 | 3.02e-11 |
| AES-256-CBC, AES-NI off | 268.8 | 264.9–271.5 | 455.4 | 2.474 | 3.02e-11 |
| 3DES-CBC | 33.08 | 32.8–33.3 | 33.53 | 20.1 | 3.02e-11 |
| Blowfish-CBC | 173.3 | 171.4–173.6 | 192.2 | 3.838 | 3.02e-11 |
Ratio > 1 means Ascon is faster than that scheme; < 1 means slower.

## Table 6.4 — Memory, expansion and key setup
| Scheme | Peak memory, streaming encrypt (MB) | Ciphertext expansion (%) | Key setup (µs) |
| --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 8.97 | 0.02448 | 0.9648 |
| AES-128-GCM, AES-NI on | 9.23 | 0.02448 | 3.889 |
| AES-128-GCM, AES-NI off | — | 0.02448 | 4.274 |
| ChaCha20-Poly1305 | 9.22 | 0.02448 | 3.908 |
| AES-256-CBC, AES-NI on | 9.2 | 0.0001 | 4.048 |
| AES-256-CBC, AES-NI off | — | 0.0001 | 4.165 |
| 3DES-CBC | 9.2 | 9e-05 | 3.427 |
| Blowfish-CBC | 9.21 | 9e-05 | 26.1 |
Peak memory is the whole process (program, OpenSSL and buffers) while streaming the largest end-to-end file. Key setup = header digest + key derivation + cipher key schedule. AES-NI-off rows have no streaming memory figure because the end-to-end test runs with default settings.

## Table 6.5 — Ascon throughput versus chunk size (100 MB)
| Chunk size | Encrypt MB/s | Decrypt MB/s | Expansion (%) |
| --- | --- | --- | --- |
| 4 KiB | 650.1 | 663.3 | 0.3907 |
| 16 KiB | 661.2 | 676.6 | 0.09773 |
| 64 KiB | 666.6 | 682.5 | 0.02448 |
| 256 KiB | 670.4 | 684.2 | 0.006174 |
| 1024 KiB | 670.9 | 683.4 | 0.001596 |
Expansion computed from the format (66-byte fixed header + 8-byte file name + 16-byte tag per chunk).

## Table 6.6 — Avalanche effect (% of output bits changed, ideal 50%)
| Scheme | region | key | plaintext |
| --- | --- | --- | --- |
| 3DES-CBC | ciphertext | 50.03 | 24.90 |
| AES-128-GCM, AES-NI on | ciphertext+tag | 49.97 | 0.78 |
| AES-128-GCM, AES-NI on | tag_only | 49.78 | 49.90 |
| AES-256-CBC, AES-NI on | ciphertext | 50.00 | 25.82 |
| Ascon-AEAD128 (proposed) | ciphertext+tag | 49.99 | 24.94 |
| Ascon-AEAD128 (proposed) | tag_only | 49.94 | 50.12 |
| Blowfish-CBC | ciphertext | 50.01 | 24.86 |
| ChaCha20-Poly1305 | ciphertext+tag | 50.02 | 0.78 |
| ChaCha20-Poly1305 | tag_only | 49.96 | 50.15 |
1 KB inputs, same nonce/IV for both encryptions (measurement only).

## Table 6.7 — End-to-end time from disk (median seconds)
| Scheme | 100 MB encrypt (s) | 100 MB decrypt (s) | 500 MB encrypt (s) | 500 MB decrypt (s) |
| --- | --- | --- | --- | --- |
| Ascon-AEAD128 (proposed) | 0.231 | 0.220 | 3.083 | 3.357 |
| AES-128-GCM, AES-NI on | 0.104 | 0.093 | 2.509 | 2.208 |
| ChaCha20-Poly1305 | 0.118 | 0.116 | 2.940 | 4.003 |
| AES-256-CBC, AES-NI on | 0.183 | 0.091 | 2.877 | 2.973 |
| 3DES-CBC | 3.113 | 3.073 | 16.927 | 16.183 |
| Blowfish-CBC | 0.651 | 0.598 | 4.336 | 3.783 |
Includes reading the input file, encryption or decryption, and writing the output file.
