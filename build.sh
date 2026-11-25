#!/usr/bin/env bash
# Build ascon-file-bench. Works in MSYS2 "UCRT64" shell on Windows and on Linux.
# Usage: ./build.sh            (Ascon opt64 implementation, default)
#        ASCON_IMPL=ref ./build.sh
set -euo pipefail
cd "$(dirname "$0")"
CC=${CC:-gcc}
CFLAGS=${CFLAGS:-"-O3 -march=native"}
IMPL=${ASCON_IMPL:-opt64}
A=third_party/ascon-c
mkdir -p build/obj
rm -f build/obj/*.o

for f in $A/crypto_aead/asconaead128/$IMPL/*.c; do
  $CC $CFLAGS -I$A/crypto_aead/asconaead128/$IMPL -I$A/tests -c "$f" -o build/obj/aead_$(basename "$f" .c).o
done
# Ascon-Hash256 and Ascon-CXOF128 both define crypto_hash(); rename at compile time.
for f in $A/crypto_hash/asconhash256/opt64/*.c; do
  $CC $CFLAGS -Dcrypto_hash=ascon_hash256 -Dascon_xof=ascon_hash256_xof \
     -I$A/crypto_hash/asconhash256/opt64 -I$A/tests -c "$f" -o build/obj/hash_$(basename "$f" .c).o
done
for f in $A/crypto_cxof/asconcxof128/ref/*.c; do
  $CC $CFLAGS -Dcrypto_hash=ascon_cxof_hash_unused \
     -I$A/crypto_cxof/asconcxof128/ref -I$A/tests -c "$f" -o build/obj/cxof_$(basename "$f" .c).o
done

LIBS="-lcrypto -lm"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) LIBS="$LIBS -lpsapi";; esac
$CC $CFLAGS -Wall -Wextra -o build/bench src/bench.c build/obj/*.o $LIBS
echo "Built build/bench (Ascon implementation: $IMPL, flags: $CFLAGS, compiler: $($CC --version | head -1))"
