#!/usr/bin/env python3
"""
RepoGuardian scanner — improved patterns, ignore paths, colored output.
Usage:
  python scanner.py file1 file2 ...
  python scanner.py       # scans tracked files (useful in CI)
  python scanner.py --staged file1 ...  # scan staged/index content
"""
import argparse
import ast
import hashlib
import hmac
import json
import math
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# optional deps
try:
    import yaml
    import git
    from colorama import init as colorama_init, Fore, Style
except Exception as e:
    print("[RepoGuardian] Missing dependency:", e)
    print("Run: pip install GitPython pyyaml colorama")
    sys.exit(2)

colorama_init(autoreset=True)

# --- detection patterns (extend as needed) ---
PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                          # AWS access key
    re.compile(r'(?i)sk_live_[0-9a-zA-Z]{24}'),               # Stripe secret
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                    # Google API key
    re.compile(r'(?i)ghp_[A-Za-z0-9_]{36}'),                  # GitHub PAT
    re.compile(r'(?i)xox[baprs]-[0-9A-Za-z\-_]{10,}'),        # Slack tokens
    re.compile(r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}'),  # JWT
    re.compile(r'(?i)(postgresql|postgres|mysql|mongodb|redis)://[^\s\'"]+'),        # DB URIs
    re.compile(r'(?i)secret[_-]?key\s*[:=]\s*[\'"][0-9A-Za-z/\+=]{8,}[\'"]'),        # generic secret assignment
]

DEFAULT_SCAN_EXTS = [".py", ".js", ".env", ".yaml", ".yml", ".json", ".tf", ".sh"]
DEFAULT_BLOCK_EXTS = [".pem", ".pfx", ".key"]
DEFAULT_IGNORE_PATHS = ["venv", ".venv", "node_modules", "dist", "build", ".git"]

# --- config loader ---
def load_config():
    cfg_path = Path(".repoguardian.yml")
    cfg = {}
    if cfg_path.exists():
        try:
            cfg = yaml.safe_load(cfg_path.read_text()) or {}
        except Exception as e:
            print(f"[RepoGuardian] Error reading .repoguardian.yml: {e}")
            cfg = {}
    return {
        "allowlist_patterns": cfg.get("allowlist_patterns", []),
        "scan_file_extensions": cfg.get("scan_file_extensions", DEFAULT_SCAN_EXTS),
        "block_file_extensions": cfg.get("block_file_extensions", DEFAULT_BLOCK_EXTS),
        "min_entropy": float(cfg.get("min_entropy", 4.0)),
        "ignore_paths": cfg.get("ignore_paths", DEFAULT_IGNORE_PATHS),
        "signing_key": cfg.get("signing_key", None),
    }

def entropy(s: str):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p, 2) for p in prob])

def is_hexadecimal_or_base64_like(s: str) -> bool:
    """Heuristic to check if a string looks like a randomly generated token (e.g. base64, hex)."""
    # Tokens usually don't have spaces or typical punctuation
    if not re.match(r"^[a-zA-Z0-9/\+=_-]+$", s):
        return False
    return True

def get_repo():
    try:
        return git.Repo(".", search_parent_directories=True)
    except Exception:
        return None

def read_staged_content(repo, path):
    try:
        return repo.git.show(f":{path}")
    except Exception:
        return None

def extract_py_string_literals_with_lineno(content: str):
    """Extract string literals from Python code with line numbers (no ast.Str, avoids warnings)."""
    results = []
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                lineno = getattr(node, "lineno", None)
                results.append((lineno or 0, node.value))
    except Exception:
        pass
    return results

def is_ignored_path(path: str, ignore_list):
    p = Path(path)
    for ign in ignore_list:
        if str(p).startswith(ign) or f"/{ign}/" in str(p) or str(p).endswith(ign):
            return True
    return False

def scan_text_for_matches(text, allowlist_regexes, min_entropy):
    findings = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if any(r.search(line) for r in allowlist_regexes):
            continue
        for pat in PATTERNS:
            if pat.search(line):
                findings.append({"line": idx, "type": "regex", "match": line.strip()})
                break
        else:
            # check length and token-like format for entropy to avoid lines with lots of syntax
            for token in line.split():
                clean_token = token.replace('"', '').replace("'", "").strip()
                if len(clean_token) >= 30 and is_hexadecimal_or_base64_like(clean_token) and entropy(clean_token) >= min_entropy:
                    findings.append({"line": idx, "type": "entropy", "match": line.strip()})
                    break
    return findings

def scan_file(path, cfg, repo=None, staged=False):
    path = str(path)
    if is_ignored_path(path, cfg["ignore_paths"]):
        return []
    ext = Path(path).suffix.lower()
    findings = []
    if ext in cfg["block_file_extensions"]:
        findings.append({"line": None, "type": "blocked_filetype", "match": f"Blocked extension {ext}"})
        return findings
    if cfg["scan_file_extensions"] and ext not in cfg["scan_file_extensions"]:
        return []

    allowlist_regexes = [re.compile(p) for p in cfg["allowlist_patterns"]]
    content = None
    if staged and repo:
        content = read_staged_content(repo, path)
    if content is None:
        try:
            content = Path(path).read_text(errors="ignore")
        except Exception:
            return []

    if path.endswith(".py"):
        literal_matches = extract_py_string_literals_with_lineno(content)
        for lineno, s in literal_matches:
            if any(r.search(s) for r in allowlist_regexes):
                continue
            for pat in PATTERNS:
                if pat.search(s):
                    findings.append({"line": lineno, "type": "regex", "match": s.strip()})
                    break
            else:
                for token in s.split():
                    clean_token = token.replace('"', '').replace("'", "").strip()
                    if len(clean_token) >= 30 and is_hexadecimal_or_base64_like(clean_token) and entropy(clean_token) >= cfg["min_entropy"]:
                        findings.append({"line": lineno, "type": "entropy", "match": s.strip()})
                        break
        findings.extend(scan_text_for_matches(content, allowlist_regexes, cfg["min_entropy"]))
    else:
        findings = scan_text_for_matches(content, allowlist_regexes, cfg["min_entropy"])

    unique = []
    seen = set()
    for f in findings:
        key = (f.get("line"), f.get("type"), (f.get("match") or "")[:200])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def generate_evidence_and_bundle(repo, findings, cfg):
    commit_sha = None
    author = None
    branch = None
    remote_url = None
    try:
        if repo:
            commit_sha = repo.head.commit.hexsha
            author = repo.head.commit.author.name
            try:
                branch = repo.active_branch.name
            except Exception:
                try:
                    branch = repo.git.rev_parse("--abbrev-ref", "HEAD")
                except Exception:
                    branch = None
            try:
                remote = next(iter(repo.remotes)).urls
                remote_url = ",".join(list(remote))
            except Exception:
                remote_url = None
    except Exception:
        pass

    evidence = {
        "commit_sha": commit_sha,
        "author": author,
        "branch": branch,
        "remote": remote_url,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

    ev_json = json.dumps(evidence, sort_keys=True, indent=2)
    digest = hashlib.sha256(ev_json.encode("utf-8")).hexdigest()
    evidence["digest"] = digest

    signing_key = cfg.get("signing_key")
    if signing_key:
        sig = hmac.new(signing_key.encode("utf-8"), ev_json.encode("utf-8"), hashlib.sha256).hexdigest()
        evidence["hmac_sha256"] = sig

    Path("evidence").mkdir(exist_ok=True)
    base = (commit_sha[:7] if commit_sha else datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    json_path = Path(f"evidence/evidence_{base}.json")
    json_path.write_text(json.dumps(evidence, indent=2))

    zip_path = Path(f"evidence/evidence_{base}.zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(json_path, arcname=json_path.name)
        files_added = set()
        for f in findings:
            filename = f.get("file")
            if not filename or filename in files_added:
                continue
            files_added.add(filename)
            try:
                if repo:
                    content = None
                    try:
                        content = repo.git.show(f":{filename}")
                    except Exception:
                        content = None
                    if content is None and Path(filename).exists():
                        z.writestr(f"files/{filename}", Path(filename).read_bytes())
                    elif content is not None:
                        z.writestr(f"files/{filename}", content.encode("utf-8", errors="ignore"))
                else:
                    if Path(filename).exists():
                        z.writestr(f"files/{filename}", Path(filename).read_bytes())
            except Exception:
                pass
    return str(json_path), str(zip_path), evidence

def main():
    parser = argparse.ArgumentParser(description="RepoGuardian scanner")
    parser.add_argument("paths", nargs="*", help="files to scan (relative paths)")
    parser.add_argument("--staged", action="store_true", help="scan staged/index content where possible")
    args = parser.parse_args()

    cfg = load_config()
    repo = get_repo()

    if args.paths:
        paths = args.paths
    elif repo:
        if args.staged:
            # Only list files that are staged in the index
            try:
                paths = [p for p in repo.git.diff("--name-only", "--cached").splitlines() if p.strip()]
            except Exception:
                paths = [p for p in repo.git.ls_files().splitlines()]
        else:
            paths = [p for p in repo.git.ls_files().splitlines()]
    else:
        paths = []

    overall_findings = []
    for p in paths:
        p = p.strip()
        if not p:
            continue
        if is_ignored_path(p, cfg["ignore_paths"]):
            continue
        matches = scan_file(p, cfg, repo=repo, staged=args.staged)
        if matches:
            overall_findings.append({"file": p, "matches": matches})

    if overall_findings:
        flat = []
        for item in overall_findings:
            fpath = item["file"]
            for m in item["matches"]:
                m["file"] = fpath
                flat.append(m)
        json_path, zip_path, evidence = generate_evidence_and_bundle(repo, flat, cfg)
        print(Fore.RED + "[RepoGuardian] ❌ Secrets detected!" + Style.RESET_ALL)
        for item in overall_findings:
            f = item["file"]
            for m in item["matches"]:
                lineno = m.get("line") or "?"
                snippet = (m.get("match") or "")[:200]
                print(Fore.YELLOW + f"  - {f}:{lineno} [{m.get('type')}] -> " + Fore.CYAN + snippet + Style.RESET_ALL)
        sys.exit(1)
    else:
        print(Fore.GREEN + "[RepoGuardian] ✅ No secrets found." + Style.RESET_ALL)
        sys.exit(0)
       

if __name__ == "__main__":
    main()
