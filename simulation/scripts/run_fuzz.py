#!/usr/bin/env python3
"""Run libFuzzer with all generated artifacts outside the source checkout."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--seed-corpus", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("fuzzer_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    binary = args.binary.resolve(strict=True)
    root = args.results_root or os.environ.get("TON_FUZZ_RESULTS")
    if not root and os.environ.get("OneDrive"):
        root = Path(os.environ["OneDrive"]) / "tonGraph" / "runs"
    if not root:
        parser.error("Set --results-root or TON_FUZZ_RESULTS to the OneDrive results directory")
    root = Path(root).resolve()
    if root == repo or repo in root.parents:
        parser.error("Results must be outside the source checkout")
    extra = args.fuzzer_args
    if extra[:1] == ["--"]:
        extra = extra[1:]
    # Prevent output redirection or positional corpora from escaping this run.
    blocked = ("-artifact_prefix=", "-exact_artifact_path=", "-merge_control_file=", "-dict=", "-features_dir=")
    if any(not x.startswith("-") or x.startswith(blocked) for x in extra):
        parser.error("Use --seed-corpus for inputs; output/path overrides are not supported")
    seed = args.seed_corpus.resolve(strict=True) if args.seed_corpus else None
    if seed and not seed.is_dir():
        parser.error("--seed-corpus must be a directory")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = root / (stamp + "-" + uuid.uuid4().hex[:8])
    corpus = run / "corpus"
    crashes = run / "crashes"
    corpus.mkdir(parents=True)
    crashes.mkdir()
    if seed:
        for item in seed.iterdir():
            if item.is_file():
                shutil.copy2(item, corpus / item.name)
    command = [str(binary), str(corpus), "-artifact_prefix=" + crashes.as_posix() + "/", *extra]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True).strip())
    with binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    metadata = {"revision": revision, "dirty": dirty, "command": command,
                "binary_sha256": binary_hash,
                "seed_corpus": str(seed) if seed else None, "dry_run": args.dry_run}
    manifest = run / "run.json"
    manifest.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(run)
    if args.dry_run:
        return 0
    env = os.environ.copy()
    env["GRAPH_LOG_FILE"] = str(run / "trace.ndjson")
    env["LLVM_PROFILE_FILE"] = str(run / "%p.profraw")
    with (run / "fuzzer.log").open("wb") as log:
        result = subprocess.run(command, cwd=run, env=env, stdout=log, stderr=subprocess.STDOUT)
    metadata["exit_code"] = result.returncode
    manifest.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
