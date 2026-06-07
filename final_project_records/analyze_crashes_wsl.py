import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


ASAN_RE = re.compile(r"ERROR: AddressSanitizer: ([^\s]+)")
FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+(?:\s+in)?\s+(.+)$", re.MULTILINE)
OFFSET_RE = re.compile(r"fuzzgoat_ASAN\+0x([0-9a-fA-F]+)")
SRC_RE = re.compile(r"(/src/[^:\s)]+:\d+(?::\d+)?)")


def symbolize(repo: Path, offset_hex: str):
    try:
        proc = subprocess.run(
            ["addr2line", "-f", "-C", "-e", str(repo / "fuzzgoat_ASAN"), "0x" + offset_hex],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=2,
        )
        lines = [line.strip() for line in proc.stdout.splitlines()]
        if len(lines) >= 2:
            return {"function": lines[0], "source": lines[1]}
    except Exception:
        pass
    return {"function": "", "source": ""}


def run_one(repo: Path, sample: Path, timeout: float):
    data = sample.read_bytes()
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "abort_on_error=0:symbolize=1:detect_leaks=0"
    proc = subprocess.run(
        [str(repo / "fuzzgoat_ASAN"), str(sample)],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    asan_match = ASAN_RE.search(combined)
    frames = []
    for idx, frame in FRAME_RE.findall(combined):
        frame = frame.strip()
        offset_match = OFFSET_RE.search(frame)
        sym = symbolize(repo, offset_match.group(1)) if offset_match else {"function": "", "source": ""}
        frames.append({
            "index": int(idx),
            "frame": frame,
            "offset": offset_match.group(1) if offset_match else "",
            "function": sym["function"],
            "source": sym["source"],
        })
    locations = []
    for loc in SRC_RE.findall(combined):
        if loc not in locations:
            locations.append(loc)

    name = sample.name
    sig_match = re.search(r"sig:(\d+)", name)
    execs_match = re.search(r"execs:(\d+)", name)
    time_match = re.search(r"time:(\d+)", name)
    app_frames = [
        f for f in frames
        if f.get("source") and f["source"] != "??:?" and ("/src/" in f["source"] or f["source"].startswith("/src/"))
    ]
    symbol_locations = []
    for f in app_frames:
        loc = f"{f['function']} at {f['source']}"
        if loc not in symbol_locations:
            symbol_locations.append(loc)

    return {
        "id": name.split(",")[0].replace("id:", ""),
        "filename": name,
        "signal": sig_match.group(1) if sig_match else "",
        "execs": int(execs_match.group(1)) if execs_match else None,
        "time_ms": int(time_match.group(1)) if time_match else None,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "exit_code": proc.returncode,
        "asan_type": asan_match.group(1) if asan_match else "NO_ASAN_ERROR",
        "top_frame": frames[0]["frame"] if frames else "",
        "top_symbol": symbol_locations[0] if symbol_locations else "",
        "frames": frames[:8],
        "locations": (symbol_locations + locations)[:8],
        "stdout_head": (proc.stdout or "")[:400],
        "stderr_head": (proc.stderr or "")[:1200],
    }


def classify(item):
    t = item["asan_type"]
    locs = " ".join(item.get("locations", []))
    top = item.get("top_frame", "")
    if t == "attempting" and "free" in item.get("stderr_head", ""):
        return "invalid-free / bad-free"
    if t in {"heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow"}:
        return t
    if t == "SEGV":
        if "unknown address 0x000000000000" in item.get("stderr_head", ""):
            return "null-pointer-dereference"
        return "segmentation-fault"
    if "fuzzgoat.c:85" in locs:
        return "invalid-free / bad-free"
    if "main.c:150" in locs or "puts" in top:
        return "heap-buffer-overflow"
    return t


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    repo = Path(args.repo)
    samples = sorted((repo / "out/default/crashes").glob("id:*"))
    results = []
    for sample in samples:
        try:
            item = run_one(repo, sample, args.timeout)
        except subprocess.TimeoutExpired:
            item = {
                "id": sample.name.split(",")[0].replace("id:", ""),
                "filename": sample.name,
                "signal": "",
                "execs": None,
                "time_ms": None,
                "size": sample.stat().st_size,
                "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
                "exit_code": "TIMEOUT",
                "asan_type": "TIMEOUT",
                "top_frame": "",
                "frames": [],
                "locations": [],
                "stdout_head": "",
                "stderr_head": "",
            }
        item["classification"] = classify(item)
        results.append(item)
        print(f"{item['id']} {item['classification']} {item['asan_type']}")

    by_class = Counter(item["classification"] for item in results)
    by_asan = Counter(item["asan_type"] for item in results)
    by_signal = Counter(item["signal"] for item in results)

    groups = defaultdict(list)
    for item in results:
        key = (item["classification"], item["top_frame"], tuple(item["locations"][:3]))
        groups[str(key)].append(item["id"])

    summary = {
        "total_samples": len(results),
        "by_classification": dict(by_class),
        "by_asan_type": dict(by_asan),
        "by_signal": dict(by_signal),
        "unique_stack_groups": len(groups),
        "groups": [
            {
                "classification": key.split(",", 1)[0].strip("('"),
                "sample_count": len(ids),
                "sample_ids": ids[:12],
            }
            for key, ids in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        ],
    }
    payload = {"summary": summary, "results": results}
    Path(args.out_json).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    with Path(args.out_csv).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "id",
                "signal",
                "execs",
                "time_ms",
                "size",
                "sha256",
                "exit_code",
                "asan_type",
                "classification",
                "top_frame",
                "top_symbol",
                "locations",
                "filename",
            ],
        )
        writer.writeheader()
        for item in results:
            writer.writerow({
                "id": item["id"],
                "signal": item["signal"],
                "execs": item["execs"],
                "time_ms": item["time_ms"],
                "size": item["size"],
                "sha256": item["sha256"],
                "exit_code": item["exit_code"],
                "asan_type": item["asan_type"],
                "classification": item["classification"],
                "top_frame": item["top_frame"],
                "top_symbol": item.get("top_symbol", ""),
                "locations": "; ".join(item["locations"]),
                "filename": item["filename"],
            })

    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
