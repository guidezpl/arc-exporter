import json
import os
import re
import shutil
import subprocess
from pathlib import Path

def log(msg, lvl="*"):
    print(f"[{lvl}] {msg}")

def ensure(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_dir_name(name: str) -> str:
    s = name.strip() if isinstance(name, str) else "profile"
    s = re.sub(r"[\\/:*?\"<>|]+", "-", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s or "profile"

def read_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def write_json_atomic(path: Path, obj: dict, do_backup=True, now_suffix: str = ""):
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    if do_backup and path.exists():
        suffix = f"-{now_suffix}" if now_suffix else ""
        bak = path.with_suffix(f".bak{suffix}")
        try:
            shutil.copy2(path, bak)
            log(f"Backed up {path.name} → {bak.name}", "OK")
        except Exception as e:
            log(f"Backup failed for {path}: {e}", "!")
    tmp.replace(path)

def keychain_get(service: str) -> str | None:
    try:
        r = subprocess.run(["security", "find-generic-password", "-w", "-s", service], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None

