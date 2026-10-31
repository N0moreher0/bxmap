#!/usr/bin/env python3
"""End-to-end benchmark: bxmap vs `strings` on a synthetic memory-dump corpus.

Measures wall time, throughput and peak RSS of the whole process (I/O + scan +
output), which is what the README table reports. For pure scanner numbers use
`cargo bench`.

Usage:
    python bench/bench.py                     # 256 MiB corpus, default args
    python bench/bench.py --size-mb 64 --repeat 3
    python bench/bench.py --with-strings      # also run `strings` if installed
    python bench/bench.py --json out.json

Peak RSS needs `psutil` (`pip install psutil`); without it the RSS column is
left blank instead of guessing.
"""

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

CORPUS_ITEMS = [
    b"C:\\Windows\\System32\\kernel32.dll",
    b"C:\\Users\\victim\\Desktop\\secrets.txt",
    b"http://update.example.com/payload.exe",
    b"password=SuperSecret123",
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"SELECT * FROM users WHERE id = 42",
    b"RAR password=ExtractMeIfYouCan2024!",
    b"TEMP=C:\\Users\\victim\\AppData\\Local\\Temp",
]


def build_corpus(path, size_bytes):
    """Mixed ASCII + UTF-16LE strings separated by binary junk."""
    if os.path.exists(path) and os.path.getsize(path) >= size_bytes:
        return
    utf16 = [item.decode("ascii").encode("utf-16-le") for item in CORPUS_ITEMS]
    junk = bytes(range(128, 256))
    with open(path, "wb") as handle:
        written = 0
        index = 0
        while written < size_bytes:
            block = bytearray()
            block += junk[: 37 + (index * 17) % 200]
            block += CORPUS_ITEMS[index % len(CORPUS_ITEMS)]
            block += b"\x00\x00\x00"
            block += utf16[index % len(utf16)]
            block += b"\x00\x00\x00\x00"
            handle.write(block)
            written += len(block)
            index += 1


def find_peak_rss_sampler():
    try:
        import psutil  # noqa: F401
    except ImportError:
        return None

    import psutil

    class Sampler:
        def __init__(self, pid):
            self.process = psutil.Process(pid)
            self.peak = 0

        def sample(self):
            try:
                rss = self.process.memory_info().rss
            except psutil.Error:
                return
            self.peak = max(self.peak, rss)

        @property
        def peak_mb(self):
            return self.peak / (1024 * 1024) if self.peak else None

    return Sampler


def run_measured(command, sampler_factory):
    """Run `command`, returning (seconds, peak_rss_mb, output_bytes, exit)."""
    start = time.perf_counter()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    sampler = sampler_factory(process.pid) if sampler_factory else None
    output_len = 0
    while True:
        chunk = process.stdout.read(1 << 20)
        if chunk:
            output_len += len(chunk)
            if sampler:
                sampler.sample()
            continue
        if process.poll() is not None:
            break
        if sampler:
            sampler.sample()
            time.sleep(0.02)
    process.stdout.close()
    elapsed = time.perf_counter() - start
    peak = sampler.peak_mb if sampler else None
    return elapsed, peak, output_len, process.returncode


def find_binary(explicit):
    if explicit:
        return explicit
    for candidate in (
        os.path.join("target", "release", "bxmap-cli.exe"),
        os.path.join("target", "release", "bxmap-cli"),
        os.path.join("target", "release", "bxmap.exe"),
        os.path.join("target", "release", "bxmap"),
    ):
        if os.path.exists(candidate):
            return candidate
    found = shutil.which("bxmap-cli") or shutil.which("bxmap")
    if not found:
        sys.exit("could not find the bxmap binary; build it or pass --binary")
    return found


def summarize(label, runs, size_bytes):
    best = min(runs, key=lambda run: run[0])
    seconds = statistics.median(run[0] for run in runs)
    peaks = [run[1] for run in runs if run[1] is not None]
    return {
        "label": label,
        "seconds": seconds,
        "seconds_best": best[0],
        "mib_per_s": size_bytes / (1024 * 1024) / max(seconds, 1e-9),
        "peak_mb": max(peaks) if peaks else None,
        "output_mb": best[2] / (1024 * 1024),
        "exit": best[3],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mb", type=int, default=256)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--binary", default=None)
    parser.add_argument("--with-strings", action="store_true")
    parser.add_argument("--json", default=None)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the generated corpus in bench/.corpus.bin",
    )
    args = parser.parse_args()

    size_bytes = args.size_mb * 1024 * 1024
    bench_dir = os.path.dirname(os.path.abspath(__file__))
    if args.keep:
        corpus = os.path.join(bench_dir, ".corpus.bin")
    else:
        corpus = os.path.join(tempfile.gettempdir(), "bxmap-bench-corpus.bin")
    print(f"corpus: {corpus} ({args.size_mb} MiB)")
    build_corpus(corpus, size_bytes)

    binary = find_binary(args.binary)
    sampler_factory = find_peak_rss_sampler()
    if sampler_factory is None:
        print("note: psutil not installed -> peak RSS column will be blank")

    scenarios = [
        ("bxmap --threads 1", [binary, corpus, "--threads", "1", "--no-progress", "--max-strings", "0"]),
        ("bxmap --auto-tune", [binary, corpus, "--auto-tune", "--no-progress", "--max-strings", "0"]),
        (
            "bxmap --extract all --report summary",
            [
                binary,
                corpus,
                "--auto-tune",
                "--no-progress",
                "--max-strings",
                "0",
                "--extract",
                "all",
                "--report",
                "summary",
            ],
        ),
    ]

    results = []
    for label, command in scenarios:
        runs = []
        for _ in range(max(1, args.repeat)):
            runs.append(run_measured(command, sampler_factory)[:4])
        results.append(summarize(label, runs, size_bytes))
        print(f"  {label}: done")

    strings = shutil.which("strings") if args.with_strings else None
    if args.with_strings and not strings:
        print("note: `strings` not found in PATH; skipping the comparison")

    if strings:
        # Fair comparison: same minimum length, ASCII + UTF-16LE, and the
        # output is consumed the same way (piped, not written to a file).
        command = [strings, "-a", "-el", "-n", "4", corpus]
        runs = [run_measured(command, sampler_factory)[:4] for _ in range(max(1, args.repeat))]
        results.append(summarize("strings -a -el -n 4", runs, size_bytes))
        print("  strings: done")

    print()
    header = "| Scenario | Time (s, best of N) | Throughput | Peak RSS | Output |"
    print(header)
    print("|---|---|---|---|---|")
    for row in results:
        peak = f"{row['peak_mb']:.0f} MB" if row["peak_mb"] else "n/a"
        print(
            f"| {row['label']} | {row['seconds_best']:.2f} | "
            f"{size_bytes / (1024 * 1024) / max(row['seconds_best'], 1e-9):.0f} MiB/s | "
            f"{peak} | {row['output_mb']:.0f} MB |"
        )

    machine = {
        "cpu": platform.processor() or platform.machine(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "size_mb": args.size_mb,
        "repeat": args.repeat,
    }
    print()
    print("machine:", json.dumps(machine))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump({"machine": machine, "results": results}, handle, indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
