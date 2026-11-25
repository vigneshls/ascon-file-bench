"""Run every experiment for the Ascon file-encryption manuscript.

Usage (from the project folder):
    python run_all.py            # full run, about 45-60 minutes on a Ryzen 5 5600H
    python run_all.py --quick    # 2-minute check that everything works (results NOT for the paper)

Before a full run: plug in the charger, set Windows power mode to "Best performance",
close other programs, and let the laptop sit idle for a few minutes.
Results are written to results/ (or results_quick/).
"""
import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXE = ROOT / "build" / ("bench.exe" if os.name == "nt" else "bench")
SCHEMES = ["ascon", "aes128gcm", "chacha20poly1305", "aes256cbc", "3des", "blowfish"]
AESNI_OFF = "~0x200000200000000"  # clears AES-NI (bit 57) and PCLMULQDQ (bit 33) in OpenSSL


def run(args, env_extra=None, log=None, check=True):
    env = os.environ.copy()
    env.pop("OPENSSL_ia32cap", None)
    if env_extra:
        env.update(env_extra)
    cmd = [str(EXE)] + [str(a) for a in args]
    p = subprocess.run(cmd, env=env, capture_output=True, text=True)
    out = p.stdout + p.stderr
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write("$ " + " ".join(cmd) + (f"   [{env_extra}]" if env_extra else "") + "\n" + out + "\n")
    if check and p.returncode != 0:
        print(out)
        sys.exit(f"Command failed: {' '.join(cmd)}")
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def system_info(out_dir):
    lines = [f"date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
             f"os: {platform.platform()}",
             f"machine: {platform.machine()}",
             f"processor: {platform.processor()}",
             f"python: {sys.version.split()[0]}"]
    if os.name == "nt":
        for q in (["wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed", "/format:list"],
                  ["wmic", "computersystem", "get", "Model,TotalPhysicalMemory", "/format:list"],
                  ["wmic", "diskdrive", "get", "Model,InterfaceType", "/format:list"]):
            try:
                r = subprocess.run(q, capture_output=True, text=True, timeout=30).stdout
                lines += [l.strip() for l in r.splitlines() if l.strip()]
            except Exception as e:  # wmic is missing on some Windows 11 builds
                lines.append(f"{q[1]}: unavailable ({e})")
    lines.append(run(["info"]).strip())
    (out_dir / "system.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="tiny run to test the setup")
    a = ap.parse_args()

    if not EXE.exists():
        sys.exit(f"{EXE} not found. Run ./build.sh first.")
    out = ROOT / ("results_quick" if a.quick else "results")
    if out.exists():
        stamp = time.strftime("%Y%m%d-%H%M%S")
        shutil.move(str(out), str(out) + "_old_" + stamp)
        print(f"Previous results moved to {out.name}_old_{stamp}")
    out.mkdir()
    log = out / "run_log.txt"
    tmp = ROOT / "tmp_files"
    tmp.mkdir(exist_ok=True)

    runs, runs_big, chunk_runs, e2e_runs = (2, 1, 2, 1) if a.quick else (30, 10, 30, 5)
    env_q = {"BENCH_MAX_MB": "10"} if a.quick else {}
    t0 = time.time()

    print("\n[1/7] System information"); system_info(out)

    print("\n[2/7] Self-test (known-answer tests + round trips)")
    r = run(["selftest"], log=log); print(r); (out / "selftest.txt").write_text(r)

    print("[3/7] Tamper-detection tests")
    r = run(["tamper"], log=log); print(r); (out / "tamper.txt").write_text(r)

    print(f"[4/7] Speed: all schemes, AES-NI on ({runs} runs; {runs_big} runs at 500 MB)")
    run(["speed", out / "speed.csv", runs, runs_big], env_q, log)
    print("      Speed: AES schemes, AES-NI off")
    run(["speed", out / "speed.csv", runs, runs_big, "aes128gcm,aes256cbc"],
        {**env_q, "OPENSSL_ia32cap": AESNI_OFF}, log)

    print(f"[5/7] Chunk-size sweep ({chunk_runs} runs) and key setup")
    run(["chunk", out / "chunk.csv", chunk_runs], None, log)
    run(["keysetup", out / "keysetup.csv", 200 if a.quick else 10000], None, log)
    run(["keysetup", out / "keysetup.csv", 200 if a.quick else 10000], {"OPENSSL_ia32cap": AESNI_OFF}, log)

    print("[6/7] Avalanche effect")
    run(["aval", out / "avalanche.csv", 100 if a.quick else 1000], None, log)

    print(f"[7/7] End-to-end file encryption from disk ({e2e_runs} runs per scheme and size)")
    sizes = [10] if a.quick else [100, 500]
    free_gb = shutil.disk_usage(ROOT).free / 2**30
    need_gb = max(sizes) * 3 / 1024 + 0.5
    if free_gb < need_gb:
        sys.exit(f"Only {free_gb:.1f} GB free; need about {need_gb:.1f} GB for the end-to-end test.")
    for mb in sizes:
        src = tmp / f"plain_{mb}MB.bin"
        run(["mkfile", src, mb])
        ref = sha256(src)
        for rep in range(e2e_runs):
            for s in SCHEMES:
                enc, dec = tmp / f"{s}.enc", tmp / f"{s}.dec"
                run(["encfile", s, src, enc, out / "e2e.csv"], None, log)
                run(["decfile", enc, dec, out / "e2e.csv"], None, log)
                if sha256(dec) != ref:
                    sys.exit(f"End-to-end verification failed for {s}")
                enc.unlink(); dec.unlink()
            print(f"      {mb} MB run {rep + 1}/{e2e_runs} verified")
        src.unlink()
    shutil.rmtree(tmp, ignore_errors=True)

    print(f"\nAll experiments finished in {(time.time() - t0) / 60:.1f} minutes. Results in {out}")
    print(f"Next: python analyze.py {out.name}")


if __name__ == "__main__":
    main()
