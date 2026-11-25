/*
 * ascon-file-bench: chunked authenticated file encryption with Ascon
 * (NIST SP 800-232) and a benchmark against AES-128-GCM, ChaCha20-Poly1305,
 * AES-256-CBC, 3DES-CBC and Blowfish-CBC (OpenSSL EVP).
 *
 * Commands
 *   bench selftest
 *   bench tamper
 *   bench speed    <out.csv> [runs] [runs_500MB]
 *   bench chunk    <out.csv> [runs]
 *   bench keysetup <out.csv> [iterations]
 *   bench aval     <out.csv> [trials]
 *   bench encfile  <scheme> <in> <out> <csv>   (streams from disk; logs time + peak memory)
 *   bench decfile  <scheme> <in> <out> <csv>
 *   bench mkfile   <path> <size_MB>
 *
 * Schemes: ascon, aes128gcm, chacha20poly1305, aes256cbc, 3des, blowfish
 * Set OPENSSL_ia32cap=~0x200000200000000 before starting the program to
 * disable AES-NI and PCLMULQDQ in OpenSSL (the program reports the setting).
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sched.h>
#include <sys/resource.h>
#include <time.h>
#endif

/* ---- Ascon reference implementation (ascon-c, renamed at compile time) */
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec, const unsigned char *c,
                        unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub,
                        const unsigned char *k);
int ascon_hash256(unsigned char *out, const unsigned char *in,
                  unsigned long long inlen);
int crypto_cxof(unsigned char *out, unsigned long long outlen,
                const unsigned char *in, unsigned long long inlen,
                const unsigned char *cs, unsigned long long cslen);

/* ------------------------------------------------------------ utilities */
static void die(const char *msg) {
  fprintf(stderr, "ERROR: %s\n", msg);
  ERR_print_errors_fp(stderr);
  exit(2);
}
static void *xmalloc(size_t n) {
  void *p = malloc(n ? n : 1);
  if (!p) die("out of memory");
  return p;
}
static void rnd(uint8_t *b, size_t n) {
  /* RAND_bytes takes an int; fill large buffers in pieces */
  while (n) {
    int k = n > (1u << 30) ? (1 << 30) : (int)n;
    if (RAND_bytes(b, k) != 1) die("RAND_bytes");
    b += k;
    n -= (size_t)k;
  }
}
static void st64(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t ld64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
  return v;
}
static void wipe(void *p, size_t n) { OPENSSL_cleanse(p, n); }

static double now_ns(void) {
#ifdef _WIN32
  static LARGE_INTEGER f;
  LARGE_INTEGER t;
  if (!f.QuadPart) QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&t);
  return (double)t.QuadPart * 1e9 / (double)f.QuadPart;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
#endif
}
static double peak_mem_mb(void) {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc))
    return (double)pmc.PeakWorkingSetSize / (1024.0 * 1024.0);
  return -1;
#else
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (double)ru.ru_maxrss / 1024.0; /* KB on Linux */
#endif
}
static void pin_to_core(int core) {
#ifdef _WIN32
  SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << core);
  SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#else
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(core, &s);
  sched_setaffinity(0, sizeof s, &s);
#endif
}
static const char *aesni_label(void) {
  const char *e = getenv("OPENSSL_ia32cap");
  return (e && *e) ? "off" : "on";
}

/* ------------------------------------------------------------- schemes */
enum { S_ASCON, S_GCM, S_CHACHA, S_CBC, S_3DES, S_BF, S_COUNT };
static const char *SNAME[S_COUNT] = {"ascon",     "aes128gcm", "chacha20poly1305",
                                     "aes256cbc", "3des",      "blowfish"};
static const int KEYLEN[S_COUNT] = {16, 16, 32, 32, 24, 16};
static const int IS_AEAD[S_COUNT] = {1, 1, 1, 0, 0, 0};

static int scheme_id(const char *n) {
  for (int i = 0; i < S_COUNT; i++)
    if (!strcmp(n, SNAME[i])) return i;
  return -1;
}
static const EVP_CIPHER *evp_cipher(int s) {
  switch (s) {
    case S_GCM: return EVP_aes_128_gcm();
    case S_CHACHA: return EVP_chacha20_poly1305();
    case S_CBC: return EVP_aes_256_cbc();
    case S_3DES: return EVP_des_ede3_cbc();
    case S_BF: return EVP_bf_cbc();
  }
  return NULL;
}

#define MAGIC "ASCF"
#define HDR_FIXED 66 /* magic4 ver1 scheme1 chunk4 salt32 r8 ptlen8 metalen2 + meta */
#define TAG 16
#define AD_LEN 41   /* H(32) || i(8) || f(1) */
#define MAX_META 512

typedef struct {
  int s;
  uint32_t B;
  uint64_t ptlen, n; /* plaintext length, number of chunks */
  uint8_t hdr[HDR_FIXED + MAX_META];
  size_t hlen;
  uint8_t H[32];
  uint8_t K[32];
  uint8_t r[8];
  uint8_t iv[16];
  EVP_CIPHER_CTX *ctx;
} fctx;

static uint64_t nchunks(uint64_t ptlen, uint32_t B) {
  return ptlen == 0 ? 1 : (ptlen + B - 1) / B;
}

/* Header digest and per-file key.
 * Ascon: H = Ascon-Hash256(header), K = Ascon-CXOF128(MK||salt, "ASCON-FILE-v1/enc", 128)
 * Baselines: same structure with SHA-256 and HKDF-SHA256 so the file
 * format is identical and only the primitives differ. */
static void derive(fctx *f, const uint8_t mk[16], const uint8_t salt[32]) {
  static const char LABEL[] = "ASCON-FILE-v1/enc";
  if (f->s == S_ASCON) {
    uint8_t x[48];
    memcpy(x, mk, 16);
    memcpy(x + 16, salt, 32);
    ascon_hash256(f->H, f->hdr, f->hlen);
    crypto_cxof(f->K, 16, x, 48, (const uint8_t *)LABEL, sizeof LABEL - 1);
    wipe(x, sizeof x);
  } else {
    unsigned int hl = 32;
    if (!EVP_Digest(f->hdr, f->hlen, f->H, &hl, EVP_sha256(), NULL)) die("sha256");
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM p[5], *q = p;
    *q++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)mk, 16);
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, 32);
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)LABEL,
                                             sizeof LABEL - 1);
    *q = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kc, f->K, (size_t)KEYLEN[f->s], p) != 1) die("hkdf");
    EVP_KDF_CTX_free(kc);
    EVP_KDF_free(kdf);
  }
}

static size_t build_header(uint8_t *h, int s, uint32_t B, const uint8_t salt[32],
                           const uint8_t r[8], uint64_t ptlen, const char *meta) {
  size_t ml = meta ? strlen(meta) : 0;
  if (ml > MAX_META) ml = MAX_META;
  memcpy(h, MAGIC, 4);
  h[4] = 1;
  h[5] = (uint8_t)s;
  h[6] = (uint8_t)B; h[7] = (uint8_t)(B >> 8); h[8] = (uint8_t)(B >> 16); h[9] = (uint8_t)(B >> 24);
  memcpy(h + 10, salt, 32);
  memcpy(h + 42, r, 8);
  st64(h + 50, ptlen);
  h[58] = (uint8_t)ml; h[59] = (uint8_t)(ml >> 8);
  memset(h + 60, 0, 6); /* reserved */
  if (ml) memcpy(h + HDR_FIXED, meta, ml);
  return HDR_FIXED + ml;
}

/* Prepare context from a header (shared by encrypt and decrypt). */
static int ctx_from_header(fctx *f, const uint8_t mk[16], const uint8_t *h, size_t avail) {
  if (avail < HDR_FIXED || memcmp(h, MAGIC, 4) || h[4] != 1) return -1;
  size_t ml = (size_t)h[58] | ((size_t)h[59] << 8);
  if (ml > MAX_META || avail < HDR_FIXED + ml) return -1;
  f->s = h[5];
  if (f->s >= S_COUNT) return -1;
  f->B = (uint32_t)h[6] | ((uint32_t)h[7] << 8) | ((uint32_t)h[8] << 16) | ((uint32_t)h[9] << 24);
  if (f->B == 0 || f->B > (64u << 20)) return -1;
  f->ptlen = ld64(h + 50);
  f->n = nchunks(f->ptlen, f->B);
  memcpy(f->r, h + 42, 8);
  f->hlen = HDR_FIXED + ml;
  memcpy(f->hdr, h, f->hlen);
  derive(f, mk, h + 10);
  if (f->s != S_ASCON) {
    f->ctx = EVP_CIPHER_CTX_new();
    if (!f->ctx) die("ctx");
  }
  return 0;
}
static void ctx_free(fctx *f) {
  if (f->ctx) EVP_CIPHER_CTX_free(f->ctx);
  f->ctx = NULL;
  wipe(f->K, sizeof f->K);
}

static void chunk_nonce_ad(const fctx *f, uint64_t i, uint8_t nonce[16], uint8_t ad[AD_LEN]) {
  /* Ascon: N_i = r(8) || i(8). GCM/ChaCha (96-bit nonce): r[0..3] || i(8). */
  if (f->s == S_ASCON) {
    memcpy(nonce, f->r, 8);
    st64(nonce + 8, i);
  } else {
    memcpy(nonce, f->r, 4);
    st64(nonce + 4, i);
  }
  memcpy(ad, f->H, 32);
  st64(ad + 32, i);
  ad[40] = (uint8_t)(i == f->n - 1);
}

/* AEAD chunk: out = C_i || T_i (len + 16 bytes). */
static void aead_enc_chunk(fctx *f, uint64_t i, const uint8_t *in, size_t len, uint8_t *out) {
  uint8_t nonce[16], ad[AD_LEN];
  chunk_nonce_ad(f, i, nonce, ad);
  if (f->s == S_ASCON) {
    unsigned long long cl;
    crypto_aead_encrypt(out, &cl, in, len, ad, AD_LEN, NULL, nonce, f->K);
    return;
  }
  int l;
  if (i == 0 && !EVP_EncryptInit_ex(f->ctx, evp_cipher(f->s), NULL, f->K, NULL)) die("init");
  if (!EVP_EncryptInit_ex(f->ctx, NULL, NULL, NULL, nonce)) die("iv");
  if (!EVP_EncryptUpdate(f->ctx, NULL, &l, ad, AD_LEN)) die("aad");
  if (len && !EVP_EncryptUpdate(f->ctx, out, &l, in, (int)len)) die("enc");
  if (!EVP_EncryptFinal_ex(f->ctx, out + len, &l)) die("final");
  if (!EVP_CIPHER_CTX_ctrl(f->ctx, EVP_CTRL_AEAD_GET_TAG, TAG, out + len)) die("tag");
}
/* returns 0 if authentic */
static int aead_dec_chunk(fctx *f, uint64_t i, const uint8_t *in, size_t clen, uint8_t *out) {
  uint8_t nonce[16], ad[AD_LEN];
  if (clen < TAG) return -1;
  chunk_nonce_ad(f, i, nonce, ad);
  size_t len = clen - TAG;
  if (f->s == S_ASCON) {
    unsigned long long ml;
    return crypto_aead_decrypt(out, &ml, NULL, in, clen, ad, AD_LEN, nonce, f->K) ? -1 : 0;
  }
  int l;
  if (i == 0 && !EVP_DecryptInit_ex(f->ctx, evp_cipher(f->s), NULL, f->K, NULL)) die("init");
  if (!EVP_DecryptInit_ex(f->ctx, NULL, NULL, NULL, nonce)) die("iv");
  if (!EVP_DecryptUpdate(f->ctx, NULL, &l, ad, AD_LEN)) die("aad");
  if (len && !EVP_DecryptUpdate(f->ctx, out, &l, in, (int)len)) die("dec");
  if (!EVP_CIPHER_CTX_ctrl(f->ctx, EVP_CTRL_AEAD_SET_TAG, TAG, (void *)(in + len))) die("settag");
  return EVP_DecryptFinal_ex(f->ctx, out + len, &l) == 1 ? 0 : -1;
}

/* ---------------------------------------------------- in-memory format */
/* Encrypt a buffer to the file format. Returns output length.
 * out must hold hdr + ptlen + 16*n + 32 bytes. */
static size_t enc_buf(int s, const uint8_t mk[16], uint32_t B, const uint8_t *pt,
                      uint64_t ptlen, const char *meta, uint8_t *out) {
  fctx f = {0};
  uint8_t salt[32], r[8];
  rnd(salt, 32);
  rnd(r, 8);
  size_t hl = build_header(out, s, B, salt, r, ptlen, meta);
  ctx_from_header(&f, mk, out, hl);
  uint8_t *o = out + hl;
  if (IS_AEAD[s]) {
    for (uint64_t i = 0; i < f.n; i++) {
      size_t len = (i == f.n - 1) ? (size_t)(ptlen - i * B) : B;
      aead_enc_chunk(&f, i, pt + i * B, len, o);
      o += len + TAG;
    }
  } else {
    int bs = EVP_CIPHER_block_size(evp_cipher(s)), l;
    rnd(f.iv, (size_t)bs);
    memcpy(o, f.iv, (size_t)bs);
    o += bs;
    if (!EVP_EncryptInit_ex(f.ctx, evp_cipher(s), NULL, f.K, f.iv)) die("cbc init");
    for (uint64_t off = 0; off < ptlen; off += B) {
      size_t len = (ptlen - off < B) ? (size_t)(ptlen - off) : B;
      if (!EVP_EncryptUpdate(f.ctx, o, &l, pt + off, (int)len)) die("cbc enc");
      o += l;
    }
    if (!EVP_EncryptFinal_ex(f.ctx, o, &l)) die("cbc final");
    o += l;
  }
  ctx_free(&f);
  return (size_t)(o - out);
}
/* Decrypt. Returns plaintext length, or -1 on any authentication/format failure. */
static int64_t dec_buf(const uint8_t mk[16], const uint8_t *ct, size_t ctlen, uint8_t *out) {
  fctx f = {0};
  if (ctx_from_header(&f, mk, ct, ctlen)) return -1;
  const uint8_t *c = ct + f.hlen, *end = ct + ctlen;
  int64_t res = -1;
  if (IS_AEAD[f.s]) {
    for (uint64_t i = 0; i < f.n; i++) {
      size_t len = (i == f.n - 1) ? (size_t)(f.ptlen - i * f.B) : f.B;
      if ((size_t)(end - c) < len + TAG) goto done;          /* truncated */
      if (aead_dec_chunk(&f, i, c, len + TAG, out + i * f.B)) goto done;
      c += len + TAG;
    }
    if (c != end) goto done;                                 /* trailing data */
    res = (int64_t)f.ptlen;
  } else {
    int bs = EVP_CIPHER_block_size(evp_cipher(f.s)), l;
    if (end - c < bs) goto done;
    if (!EVP_DecryptInit_ex(f.ctx, evp_cipher(f.s), NULL, f.K, c)) die("cbc init");
    c += bs;
    uint8_t *o = out;
    while (c < end) {
      size_t len = (size_t)(end - c) < f.B ? (size_t)(end - c) : f.B;
      if (!EVP_DecryptUpdate(f.ctx, o, &l, c, (int)len)) goto done;
      o += l;
      c += len;
    }
    if (EVP_DecryptFinal_ex(f.ctx, o, &l) != 1) goto done;
    o += l;
    res = (int64_t)(o - out);
  }
done:
  ctx_free(&f);
  return res;
}
static size_t ct_capacity(uint64_t ptlen, uint32_t B) {
  return HDR_FIXED + MAX_META + ptlen + TAG * nchunks(ptlen, B) + 32;
}

/* ------------------------------------------------------------ selftest */
static void load_providers(void) {
  if (!OSSL_PROVIDER_load(NULL, "default")) die("default provider");
  if (!OSSL_PROVIDER_load(NULL, "legacy"))
    die("legacy provider (needed for Blowfish) not found: check OPENSSL_MODULES / install");
}

static int hexeq(const uint8_t *b, size_t n, const char *hex) {
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1 || b[i] != (uint8_t)v) return 0;
  }
  return 1;
}
/* Count = 1 vectors from the KAT files shipped with ascon-c:
 * LWC_AEAD_KAT_128_128.txt, LWC_HASH_KAT_128_256.txt, LWC_CXOF_KAT_128_512.txt */
static int check_kat(void) {
  int ok = 1;
  uint8_t k[16], n[16], c[16], h[64];
  unsigned long long cl;
  for (int i = 0; i < 16; i++) { k[i] = (uint8_t)i; n[i] = (uint8_t)(0x10 + i); }
  crypto_aead_encrypt(c, &cl, NULL, 0, NULL, 0, NULL, n, k);
  int a = cl == 16 && hexeq(c, 16, "4F9C278211BEC9316BF68F46EE8B2EC6");
  ascon_hash256(h, NULL, 0);
  int b = hexeq(h, 32, "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2");
  crypto_cxof(h, 64, NULL, 0, NULL, 0);
  int x = hexeq(h, 64, "4F50159EF70BB3DAD8807E034EAEBD44C4FA2CBBC8CF1F05511AB66CDCC52990"
                       "5CA12083FC186AD899B270B1473DC5F7EC88D1052082DCDFE69FB75D269E7B74");
  printf("KAT Ascon-AEAD128 %s | Ascon-Hash256 %s | Ascon-CXOF128 %s\n", a ? "PASS" : "FAIL",
         b ? "PASS" : "FAIL", x ? "PASS" : "FAIL");
  ok = a && b && x;
  return ok;
}

static int cmd_selftest(void) {
  int fails = 0;
  if (!check_kat()) fails++;
  uint8_t mk[16];
  rnd(mk, 16);
  const uint64_t sizes[] = {0, 1, 15, 16, 17, 65535, 65536, 65537, 1000003};
  for (int s = 0; s < S_COUNT; s++) {
    int ok = 1;
    for (size_t z = 0; z < sizeof sizes / sizeof *sizes; z++) {
      uint64_t L = sizes[z];
      uint8_t *p = xmalloc(L), *c = xmalloc(ct_capacity(L, 65536)), *d = xmalloc(L + 64);
      rnd(p, L);
      size_t cl = enc_buf(s, mk, 65536, p, L, "test.bin", c);
      int64_t dl = dec_buf(mk, c, cl, d);
      if (dl != (int64_t)L || (L && memcmp(p, d, L))) ok = 0;
      free(p); free(c); free(d);
    }
    printf("round-trip %-17s %s\n", SNAME[s], ok ? "PASS" : "FAIL");
    fails += !ok;
  }
  return fails ? 1 : 0;
}

/* -------------------------------------------------------------- tamper */
static int cmd_tamper(void) {
  const uint32_t B = 65536;
  const uint64_t L = 1u << 20; /* 1 MiB = 16 chunks */
  uint8_t mk[16];
  rnd(mk, 16);
  uint8_t *p = xmalloc(L), *c = xmalloc(ct_capacity(L, B)), *c2 = xmalloc(ct_capacity(L, B)),
          *t = xmalloc(ct_capacity(L, B)), *d = xmalloc(L + 64);
  rnd(p, L);
  int fails = 0;
  for (int s = 0; s < S_COUNT; s++) {
    size_t cl = enc_buf(s, mk, B, p, L, "report.pdf", c);
    size_t cl2 = enc_buf(s, mk, B, p, L, "report.pdf", c2); /* same content, other file */
    size_t hl = HDR_FIXED + strlen("report.pdf");
    size_t cs = B + TAG; /* AEAD stored chunk size */
    struct { const char *name; int applicable; } tests[] = {
        {"clean file accepted", 1},       {"ciphertext bit flipped", 1},
        {"chunks 2 and 3 swapped", 1},    {"last chunk removed", 1},
        {"header file name edited", 1},   {"chunk spliced from other file", 1},
        {"wrong master key", 1}};
    printf("\n[%s]\n", SNAME[s]);
    for (int k = 0; k < 7; k++) {
      size_t tl = cl;
      memcpy(t, c, cl);
      uint8_t key[16];
      memcpy(key, mk, 16);
      switch (k) {
        case 1: t[hl + 100 + (IS_AEAD[s] ? 0 : 16)] ^= 0x01; break;
        case 2:
          if (IS_AEAD[s]) {
            memcpy(t + hl + 2 * cs, c + hl + 3 * cs, cs);
            memcpy(t + hl + 3 * cs, c + hl + 2 * cs, cs);
          } else { /* swap two 64 KiB-aligned ciphertext regions */
            size_t o = hl + EVP_CIPHER_block_size(evp_cipher(s));
            memcpy(t + o + 2 * B, c + o + 3 * B, B);
            memcpy(t + o + 3 * B, c + o + 2 * B, B);
          }
          break;
        case 3: tl = IS_AEAD[s] ? cl - cs : cl - B; break;
        case 4: t[HDR_FIXED] ^= 0x20; break; /* 'r' -> 'R' */
        case 5:
          if (IS_AEAD[s]) memcpy(t + hl + 5 * cs, c2 + hl + 5 * cs, cs);
          else {
            size_t o = hl + EVP_CIPHER_block_size(evp_cipher(s));
            memcpy(t + o + 5 * B, c2 + o + 5 * B, B);
          }
          break;
        case 6: key[0] ^= 1; break;
      }
      int64_t r = dec_buf(key, t, tl, d);
      int accepted = (r == (int64_t)L && !memcmp(d, p, L)) || (r >= 0 && k != 0);
      int detected = (r < 0);
      const char *verdict;
      if (k == 0) verdict = (r == (int64_t)L && !memcmp(d, p, L)) ? "PASS (accepted)" : "FAIL";
      else verdict = detected ? "detected" : "NOT DETECTED";
      (void)accepted;
      printf("  %-32s %s\n", tests[k].name, verdict);
      if (IS_AEAD[s] && ((k == 0 && strcmp(verdict, "PASS (accepted)")) || (k > 0 && !detected)))
        fails++;
    }
    (void)cl2;
  }
  printf("\nAEAD schemes must detect every attack. CBC schemes have no integrity check:\n"
         "a 'detected' result for them only means the PKCS#7 padding check failed by chance.\n");
  free(p); free(c); free(c2); free(t); free(d);
  return fails ? 1 : 0;
}

/* --------------------------------------------------------------- speed */
/* comma-separated scheme list membership */
static int in_list(const char *list, const char *name) {
  size_t n = strlen(name);
  for (const char *p = list; *p;) {
    const char *e = strchr(p, ',');
    size_t len = e ? (size_t)(e - p) : strlen(p);
    if (len == n && !strncmp(p, name, n)) return 1;
    if (!e) break;
    p = e + 1;
  }
  return 0;
}
static FILE *open_csv(const char *path, const char *hdr) {
  FILE *f = fopen(path, "rb");
  int exists = f != NULL;
  if (f) fclose(f);
  f = fopen(path, "a");
  if (!f) die("cannot open csv");
  if (!exists) fprintf(f, "%s\n", hdr);
  return f;
}
#define SPEED_HDR "experiment,scheme,aesni,size_bytes,chunk_bytes,run,op,time_ns,reps,peak_mem_mb"

/* Time one encryption + one decryption of buf (averaged over reps for small sizes). */
static void time_one(FILE *csv, const char *exp, int s, const uint8_t mk[16], uint32_t B,
                     const uint8_t *p, uint64_t L, uint8_t *c, uint8_t *d, int run) {
  int reps = 1;
  if (L < (8u << 20)) reps = (int)((8u << 20) / (L ? L : 1));
  if (reps > 100000) reps = 100000;
  size_t cl = 0;
  double t0 = now_ns();
  for (int k = 0; k < reps; k++) cl = enc_buf(s, mk, B, p, L, "file.bin", c);
  double te = (now_ns() - t0) / reps;
  int64_t dl = 0;
  t0 = now_ns();
  for (int k = 0; k < reps; k++) dl = dec_buf(mk, c, cl, d);
  double td = (now_ns() - t0) / reps;
  if (dl != (int64_t)L || (L && memcmp(p, d, L))) {
    fprintf(stderr, "verification failed: %s size %llu\n", SNAME[s], (unsigned long long)L);
    exit(3);
  }
  fprintf(csv, "%s,%s,%s,%llu,%u,%d,encrypt,%.0f,%d,%.1f\n", exp, SNAME[s], aesni_label(),
          (unsigned long long)L, B, run, te, reps, peak_mem_mb());
  fprintf(csv, "%s,%s,%s,%llu,%u,%d,decrypt,%.0f,%d,%.1f\n", exp, SNAME[s], aesni_label(),
          (unsigned long long)L, B, run, td, reps, peak_mem_mb());
  fflush(csv);
}

static int cmd_speed(const char *out, int runs, int runs_big, const char *only) {
  const uint64_t sizes[] = {1024, 65536, 1u << 20, 10u << 20, 100u << 20, 500u << 20};
  const int nsz = sizeof sizes / sizeof *sizes;
  const uint32_t B = 65536;
  FILE *csv = open_csv(out, SPEED_HDR);
  uint8_t mk[16];
  rnd(mk, 16);
  for (int z = 0; z < nsz; z++) {
    uint64_t L = sizes[z];
    if (getenv("BENCH_MAX_MB") && L > ((uint64_t)atoi(getenv("BENCH_MAX_MB")) << 20)) continue;
    uint8_t *p = xmalloc(L), *c = xmalloc(ct_capacity(L, B)), *d = xmalloc(L + 64);
    rnd(p, L);
    int R = (L >= (500u << 20)) ? runs_big : runs;
    printf("size %llu bytes: %d runs\n", (unsigned long long)L, R);
    for (int run = -3; run < R; run++) {        /* 3 warm-up runs (not logged) */
      for (int j = 0; j < S_COUNT; j++) {
        int s = (j + (run < 0 ? 0 : run)) % S_COUNT; /* rotate order each run */
        if (only && !in_list(only, SNAME[s])) continue;
        if (run < 0) {
          size_t cl = enc_buf(s, mk, B, p, L, "file.bin", c);
          dec_buf(mk, c, cl, d);
          continue;
        }
        time_one(csv, "speed", s, mk, B, p, L, c, d, run);
      }
      if (run >= 0) { printf("  run %d/%d done\r", run + 1, R); fflush(stdout); }
    }
    printf("\n");
    free(p); free(c); free(d);
  }
  fclose(csv);
  return 0;
}

static int cmd_chunk(const char *out, int runs) {
  const uint32_t Bs[] = {4096, 16384, 65536, 262144, 1048576};
  const uint64_t L = 100u << 20;
  FILE *csv = open_csv(out, SPEED_HDR);
  uint8_t mk[16];
  rnd(mk, 16);
  uint8_t *p = xmalloc(L), *c = xmalloc(ct_capacity(L, 4096)), *d = xmalloc(L + 64);
  rnd(p, L);
  for (int run = -2; run < runs; run++) {
    for (int j = 0; j < 5; j++) {
      if (run < 0) { size_t cl = enc_buf(S_ASCON, mk, Bs[j], p, L, "f", c); dec_buf(mk, c, cl, d); continue; }
      time_one(csv, "chunk", S_ASCON, mk, Bs[j], p, L, c, d, run);
      /* record ciphertext expansion once per chunk size */
    }
    if (run >= 0) { printf("  run %d/%d done\r", run + 1, runs); fflush(stdout); }
  }
  printf("\n");
  free(p); free(c); free(d);
  fclose(csv);
  return 0;
}

/* --------------------------------------------- key setup and expansion */
static int cmd_keysetup(const char *out, int iters) {
  FILE *csv = open_csv(out, "scheme,aesni,iterations,keysetup_ns_per_file,size_bytes,ct_bytes,expansion_pct");
  uint8_t mk[16];
  rnd(mk, 16);
  for (int s = 0; s < S_COUNT; s++) {
    /* key setup = header digest + key derivation + cipher context creation and key schedule */
    uint8_t salt[32], r[8], hdr[HDR_FIXED + MAX_META];
    rnd(salt, 32); rnd(r, 8);
    size_t hl = build_header(hdr, s, 65536, salt, r, 1 << 20, "file.bin");
    double t0 = now_ns();
    for (int k = 0; k < iters; k++) {
      fctx f = {0};
      ctx_from_header(&f, mk, hdr, hl);
      if (s != S_ASCON) {
        uint8_t iv[16] = {0};
        if (!EVP_EncryptInit_ex(f.ctx, evp_cipher(s), NULL, f.K, IS_AEAD[s] ? NULL : iv)) die("init");
      }
      ctx_free(&f);
    }
    double t = (now_ns() - t0) / iters;
    const uint64_t L = 100u << 20;
    uint8_t *p = xmalloc(L), *c = xmalloc(ct_capacity(L, 65536));
    rnd(p, L);
    size_t cl = enc_buf(s, mk, 65536, p, L, "file.bin", c);
    fprintf(csv, "%s,%s,%d,%.1f,%llu,%zu,%.5f\n", SNAME[s], aesni_label(), iters, t,
            (unsigned long long)L, cl, 100.0 * ((double)cl - (double)L) / (double)L);
    free(p); free(c);
    printf("%-17s key setup %.1f ns, expansion %.5f%%\n", SNAME[s], t,
           100.0 * ((double)cl - (double)L) / (double)L);
  }
  fclose(csv);
  return 0;
}

/* ------------------------------------------------------------ avalanche */
static int popdiff(const uint8_t *a, const uint8_t *b, size_t n) {
  int d = 0;
  for (size_t i = 0; i < n; i++) {
    uint8_t x = a[i] ^ b[i];
    while (x) { d += x & 1; x >>= 1; }
  }
  return d;
}
/* Raw cipher call with a fixed key and nonce/IV (measurement only: in the
 * real format nonces are never reused). Output: ciphertext (+ tag for AEAD). */
static size_t raw_enc(int s, const uint8_t *key, const uint8_t *nonce, const uint8_t *in,
                      size_t len, uint8_t *out) {
  if (s == S_ASCON) {
    unsigned long long cl;
    crypto_aead_encrypt(out, &cl, in, len, NULL, 0, NULL, nonce, key);
    return (size_t)cl;
  }
  EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
  int l, t = 0;
  if (!EVP_EncryptInit_ex(x, evp_cipher(s), NULL, key, nonce)) die("raw init");
  if (!IS_AEAD[s]) EVP_CIPHER_CTX_set_padding(x, 0); /* 1 KB is block aligned */
  EVP_EncryptUpdate(x, out, &l, in, (int)len); t = l;
  EVP_EncryptFinal_ex(x, out + t, &l); t += l;
  if (IS_AEAD[s]) { EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, TAG, out + t); t += TAG; }
  EVP_CIPHER_CTX_free(x);
  return (size_t)t;
}
static int cmd_aval(const char *out, int trials) {
  FILE *csv = open_csv(out, "scheme,trials,flip,region,mean_pct,sd_pct");
  const size_t L = 1024;
  uint8_t p[1024], p2[1024], c1[1100], c2[1100], key[32], key2[32], nonce[16];
  for (int s = 0; s < S_COUNT; s++) {
    for (int mode = 0; mode < 2; mode++) { /* 0 = plaintext bit, 1 = key bit */
      double sum = 0, sum2 = 0, sumtag = 0;
      for (int t = 0; t < trials; t++) {
        rnd(p, L); rnd(key, 32); rnd(nonce, 16);
        memcpy(p2, p, L); memcpy(key2, key, 32);
        uint8_t rb[4];
        rnd(rb, 4);
        if (mode == 0) { size_t bit = ((size_t)rb[0] | (size_t)rb[1] << 8) % (L * 8); p2[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }
        else {
          int kb = rb[0] % (KEYLEN[s] * 8);
          if (s == S_3DES) kb = (kb / 8) * 8 + 1 + (rb[1] % 7); /* skip DES parity bit (bit 0) */
          key2[kb / 8] ^= (uint8_t)(1u << (kb % 8));
        }
        size_t n1 = raw_enc(s, key, nonce, p, L, c1);
        raw_enc(s, mode ? key2 : key, nonce, mode ? p : p2, L, c2);
        double pct = 100.0 * popdiff(c1, c2, n1) / (double)(n1 * 8);
        sum += pct; sum2 += pct * pct;
        if (IS_AEAD[s]) sumtag += 100.0 * popdiff(c1 + n1 - TAG, c2 + n1 - TAG, TAG) / 128.0;
      }
      double m = sum / trials, var = sum2 / trials - m * m;
      double sd = var > 0 ? sqrt(var) : 0;
      fprintf(csv, "%s,%d,%s,%s,%.3f,%.3f\n", SNAME[s], trials, mode ? "key" : "plaintext",
              IS_AEAD[s] ? "ciphertext+tag" : "ciphertext", m, sd);
      if (IS_AEAD[s])
        fprintf(csv, "%s,%d,%s,tag_only,%.3f,\n", SNAME[s], trials, mode ? "key" : "plaintext",
                sumtag / trials);
      printf("%-17s %-9s flip: %.2f%% of ciphertext bits changed%s\n", SNAME[s],
             mode ? "key" : "plaintext", m, IS_AEAD[s] ? " (tag included)" : "");
    }
  }
  fclose(csv);
  return 0;
}

/* ----------------------------------------------------- streaming files */
static int cmd_mkfile(const char *path, int mb) {
  FILE *f = fopen(path, "wb");
  if (!f) die("cannot create file");
  uint8_t *b = xmalloc(1u << 20);
  for (int i = 0; i < mb; i++) { rnd(b, 1u << 20); fwrite(b, 1, 1u << 20, f); }
  fclose(f);
  free(b);
  return 0;
}
static uint64_t file_size(FILE *f) {
#ifdef _WIN32
  _fseeki64(f, 0, SEEK_END);
  uint64_t n = (uint64_t)_ftelli64(f);
  _fseeki64(f, 0, SEEK_SET);
#else
  fseeko(f, 0, SEEK_END);
  uint64_t n = (uint64_t)ftello(f);
  fseeko(f, 0, SEEK_SET);
#endif
  return n;
}
static int cmd_encfile(int s, const char *in, const char *outp, const char *csvp, uint32_t B) {
  double t0 = now_ns();
  FILE *fi = fopen(in, "rb"), *fo = fopen(outp, "wb");
  if (!fi || !fo) die("cannot open files");
  uint64_t L = file_size(fi);
  uint8_t mk[16] = {0}; /* demo master key; replace with a key store or Argon2id in real use */
  fctx f = {0};
  uint8_t salt[32], r[8], hdr[HDR_FIXED + MAX_META];
  rnd(salt, 32); rnd(r, 8);
  const char *base = strrchr(in, '/'); if (!base) base = strrchr(in, '\\');
  size_t hl = build_header(hdr, s, B, salt, r, L, base ? base + 1 : in);
  ctx_from_header(&f, mk, hdr, hl);
  fwrite(hdr, 1, hl, fo);
  uint8_t *ib = xmalloc(B), *ob = xmalloc((size_t)B + 64);
  if (IS_AEAD[s]) {
    for (uint64_t i = 0; i < f.n; i++) {
      size_t len = (i == f.n - 1) ? (size_t)(L - i * B) : B;
      if (fread(ib, 1, len, fi) != len) die("read");
      aead_enc_chunk(&f, i, ib, len, ob);
      fwrite(ob, 1, len + TAG, fo);
    }
  } else {
    int bs = EVP_CIPHER_block_size(evp_cipher(s)), l;
    rnd(f.iv, (size_t)bs);
    fwrite(f.iv, 1, (size_t)bs, fo);
    if (!EVP_EncryptInit_ex(f.ctx, evp_cipher(s), NULL, f.K, f.iv)) die("init");
    size_t got;
    while ((got = fread(ib, 1, B, fi)) > 0) {
      EVP_EncryptUpdate(f.ctx, ob, &l, ib, (int)got);
      fwrite(ob, 1, (size_t)l, fo);
    }
    EVP_EncryptFinal_ex(f.ctx, ob, &l);
    fwrite(ob, 1, (size_t)l, fo);
  }
  ctx_free(&f);
  fclose(fi); fclose(fo);
  double t = now_ns() - t0;
  FILE *csv = open_csv(csvp, "experiment,scheme,aesni,size_bytes,chunk_bytes,op,time_ns,peak_mem_mb");
  fprintf(csv, "e2e,%s,%s,%llu,%u,encrypt,%.0f,%.2f\n", SNAME[s], aesni_label(), (unsigned long long)L, B, t, peak_mem_mb());
  fclose(csv);
  free(ib); free(ob);
  return 0;
}
static int cmd_decfile(const char *in, const char *outp, const char *csvp) {
  double t0 = now_ns();
  FILE *fi = fopen(in, "rb"), *fo = fopen(outp, "wb");
  if (!fi || !fo) die("cannot open files");
  (void)file_size(fi);
  uint64_t written = 0;
  uint8_t mk[16] = {0};
  uint8_t hdr[HDR_FIXED + MAX_META];
  size_t got = fread(hdr, 1, HDR_FIXED, fi);
  size_t ml = (size_t)hdr[58] | ((size_t)hdr[59] << 8);
  if (got != HDR_FIXED || ml > MAX_META || fread(hdr + HDR_FIXED, 1, ml, fi) != ml) die("bad header");
  fctx f = {0};
  if (ctx_from_header(&f, mk, hdr, HDR_FIXED + ml)) die("bad header");
  int s = f.s, ok = 1;
  uint8_t *ib = xmalloc((size_t)f.B + 64), *ob = xmalloc((size_t)f.B + 64);
  if (IS_AEAD[s]) {
    for (uint64_t i = 0; i < f.n && ok; i++) {
      size_t len = (i == f.n - 1) ? (size_t)(f.ptlen - i * f.B) : f.B;
      if (fread(ib, 1, len + TAG, fi) != len + TAG || aead_dec_chunk(&f, i, ib, len + TAG, ob)) ok = 0;
      else { fwrite(ob, 1, len, fo); written += len; }
    }
    if (ok && fgetc(fi) != EOF) ok = 0;
  } else {
    int bs = EVP_CIPHER_block_size(evp_cipher(s)), l;
    if (fread(f.iv, 1, (size_t)bs, fi) != (size_t)bs) ok = 0;
    else if (!EVP_DecryptInit_ex(f.ctx, evp_cipher(s), NULL, f.K, f.iv)) die("init");
    while (ok && (got = fread(ib, 1, f.B, fi)) > 0) {
      if (!EVP_DecryptUpdate(f.ctx, ob, &l, ib, (int)got)) ok = 0;
      else { fwrite(ob, 1, (size_t)l, fo); written += (uint64_t)l; }
    }
    if (ok && EVP_DecryptFinal_ex(f.ctx, ob, &l) == 1) { fwrite(ob, 1, (size_t)l, fo); written += (uint64_t)l; }
    else ok = 0;
  }
  ctx_free(&f);
  fclose(fi); fclose(fo);
  if (!ok) { remove(outp); fprintf(stderr, "decryption failed: file rejected\n"); return 1; }
  double t = now_ns() - t0;
  FILE *csv = open_csv(csvp, "experiment,scheme,aesni,size_bytes,chunk_bytes,op,time_ns,peak_mem_mb");
  fprintf(csv, "e2e,%s,%s,%llu,%u,decrypt,%.0f,%.2f\n", SNAME[s], aesni_label(), (unsigned long long)written, f.B, t, peak_mem_mb());
  fclose(csv);
  free(ib); free(ob);
  return 0;
}

/* ----------------------------------------------------------------- main */
int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: see header of bench.c\n");
    return 1;
  }
  load_providers();
  pin_to_core(argc > 1 && getenv("BENCH_CORE") ? atoi(getenv("BENCH_CORE")) : 2);
  const char *c = argv[1];
  if (!strcmp(c, "info")) {
    printf("openssl=%s\n", OpenSSL_version(OPENSSL_VERSION));
#ifdef __VERSION__
    printf("compiler=%s\n", __VERSION__);
#endif
    printf("aesni=%s\n", aesni_label());
    return 0;
  }
  if (!strcmp(c, "selftest")) return cmd_selftest();
  if (!strcmp(c, "tamper")) return cmd_tamper();
  if (!strcmp(c, "speed") && argc >= 3)
    return cmd_speed(argv[2], argc > 3 ? atoi(argv[3]) : 30, argc > 4 ? atoi(argv[4]) : 10,
                     argc > 5 ? argv[5] : NULL);
  if (!strcmp(c, "chunk") && argc >= 3) return cmd_chunk(argv[2], argc > 3 ? atoi(argv[3]) : 30);
  if (!strcmp(c, "keysetup") && argc >= 3) return cmd_keysetup(argv[2], argc > 3 ? atoi(argv[3]) : 10000);
  if (!strcmp(c, "aval") && argc >= 3) return cmd_aval(argv[2], argc > 3 ? atoi(argv[3]) : 1000);
  if (!strcmp(c, "mkfile") && argc >= 4) return cmd_mkfile(argv[2], atoi(argv[3]));
  if (!strcmp(c, "encfile") && argc >= 6) {
    int s = scheme_id(argv[2]);
    if (s < 0) die("unknown scheme");
    return cmd_encfile(s, argv[3], argv[4], argv[5], 65536);
  }
  if (!strcmp(c, "decfile") && argc >= 5) return cmd_decfile(argv[2], argv[3], argv[4]);
  fprintf(stderr, "unknown or incomplete command\n");
  return 1;
}
