"""Version checking and self-update (git-based, never destructive)."""

from __future__ import annotations

import json
import os
import subprocess

from .config import PKG_DIR, VERSION, load_config
from .net import http_request

ROOT = os.path.dirname(PKG_DIR)


def _parse_version(text: str):
    parts = []
    for chunk in str(text or "").strip().lstrip("v").split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def check_for_update(timeout: float = 8.0) -> dict:
    """Compare the local version with the published version.json."""
    cfg = load_config()
    url = cfg.get("update_url")
    result = {"current": VERSION, "latest": None, "update_available": False,
              "url": None, "notes": None, "error": None}
    if not url:
        result["error"] = "no update_url configured"
        return result
    response = http_request(url, timeout=timeout)
    if response.get("error"):
        result["error"] = response["error"]
        return result
    if response.get("status") != 200:
        result["error"] = f"HTTP {response.get('status')}"
        return result
    try:
        payload = json.loads(response["body"].decode("utf-8", "replace"))
    except ValueError:
        result["error"] = "invalid version.json"
        return result

    latest = payload.get("version") or payload.get("latest")
    result["latest"] = latest
    result["url"] = payload.get("url") or payload.get("homepage")
    result["notes"] = payload.get("notes")
    if latest:
        result["update_available"] = _parse_version(latest) > _parse_version(VERSION)
    return result


def self_update() -> int:
    """Update an existing git checkout in place (safe: fast-forward only)."""
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        print("Not a git checkout — re-run install.sh to update, or download the "
              "latest release zip.")
        return 1
    try:
        status = subprocess.run(["git", "-C", ROOT, "status", "--porcelain"],
                                capture_output=True, text=True, timeout=20)
        if status.stdout.strip():
            print("Local changes detected — commit or stash them before updating:")
            print(status.stdout.strip())
            return 1
        fetch = subprocess.run(["git", "-C", ROOT, "fetch", "--all", "--prune"],
                               capture_output=True, text=True, timeout=120)
        if fetch.returncode != 0:
            print(f"git fetch failed: {(fetch.stderr or '').strip()[:200]}")
            return 1
        pull = subprocess.run(["git", "-C", ROOT, "pull", "--ff-only"],
                              capture_output=True, text=True, timeout=120)
        if pull.returncode != 0:
            print(f"git pull failed: {(pull.stderr or '').strip()[:200]}")
            return 1
        print("Updated. Restart ruk_hacker to load the new version.")
        return 0
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"update failed: {exc}")
        return 1
