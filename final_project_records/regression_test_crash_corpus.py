import argparse
import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path


ASAN_ERROR_RE = re.compile(r"(ERROR: AddressSanitizer|AddressSanitizer:DEADLYSIGNAL)")


def run_sample(binary: Path, sample: Path, timeout: float):
    data = sample.read_bytes()
    proc = subprocess.run(
        [str(binary), str(sample)],
        cwd=binary.parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout,
    )
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    combined = stdout + "\n" + stderr
    signal_match = re.search(r"sig:(\d+)", sample.name)
    has_asan_error = bool(ASAN_ERROR_RE.search(combined))
    signal_crash = proc.returncode < 0
    passed = not has_asan_error and not signal_crash
    return {
        "id": sample.name.split(",")[0].replace("id:", ""),
        "filename": sample.name,
        "original_signal": signal_match.group(1) if signal_match else "",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "exit_code": proc.returncode,
        "has_asan_error": has_asan_error,
        "signal_crash": signal_crash,
        "passed": passed,
        "stderr_head": stderr[:700].replace("\n", "\\n"),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--binary", default="fuzzgoat_ASAN")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    repo = Path(args.repo)
    binary = (repo / args.binary).resolve()
    samples = sorted((repo / "out/default/crashes").glob("id:*"))
    if len(samples) != 65:
        raise SystemExit(f"Expected 65 crash samples, found {len(samples)}")

    results = []
    for sample in samples:
        try:
            row = run_sample(binary, sample, args.timeout)
        except subprocess.TimeoutExpired:
            row = {
                "id": sample.name.split(",")[0].replace("id:", ""),
                "filename": sample.name,
                "original_signal": "",
                "size": sample.stat().st_size,
                "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
                "exit_code": "TIMEOUT",
                "has_asan_error": False,
                "signal_crash": False,
                "passed": False,
                "stderr_head": "TIMEOUT",
            }
        results.append(row)
        print(f"{row['id']} {'PASS' if row['passed'] else 'FAIL'} exit={row['exit_code']}")

    passed = sum(1 for row in results if row["passed"])
    failed = len(results) - passed
    summary = {
        "total_samples": len(results),
        "passed": passed,
        "failed": failed,
        "asan_errors_after_patch": sum(1 for row in results if row["has_asan_error"]),
        "signal_crashes_after_patch": sum(1 for row in results if row["signal_crash"]),
    }

    Path(args.out_json).write_text(
        json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    with Path(args.out_csv).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "id",
                "original_signal",
                "size",
                "sha256",
                "exit_code",
                "has_asan_error",
                "signal_crash",
                "passed",
                "filename",
                "stderr_head",
            ],
        )
        writer.writeheader()
        writer.writerows(results)

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    raise SystemExit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
