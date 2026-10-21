"""Global configuration and persistent settings for RUK_HACKER."""

from __future__ import annotations

import json
import os
import stat

APP_NAME = "RUK_HACKER"
VERSION = "1.0.0"
TAGLINE = "Termux Security Toolkit"
AUTHOR = "RUK"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 13; Termux) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36 RUK-HACKER/1.0.0"
)

HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".ruk_hacker")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
REPORT_DIR = os.path.join(HOME_DIR, "ruk_reports")
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PKG_DIR, "data")

DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 60

DEFAULTS = {
    "terms_accepted": False,
    "timeout": DEFAULT_TIMEOUT,
    "threads": DEFAULT_THREADS,
    "rate": 0.0,
    "color": True,
    "report_dir": REPORT_DIR,
    "auto_save": False,
    "dns_servers": [],
    "update_url": "https://raw.githubusercontent.com/Janrahat/RUK_HACKER/main/version.json",
}

LEGAL_NOTICE = (
    "RUK_HACKER is a security auditing tool intended ONLY for systems you own\n"
    "or for targets where you have explicit written permission to test.\n"
    "Unauthorised scanning is illegal in most countries and can lead to\n"
    "criminal prosecution. You are solely responsible for your actions."
)

_CACHE = None


def load_config(reload: bool = False) -> dict:
    """Return the merged configuration dictionary."""
    global _CACHE
    if _CACHE is not None and not reload:
        return dict(_CACHE)

    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            user_cfg = json.load(fh)
        if isinstance(user_cfg, dict):
            for key, value in user_cfg.items():
                if key in DEFAULTS or key.startswith("_") is False:
                    cfg[key] = value
    except (OSError, ValueError):
        pass
    _CACHE = cfg
    return dict(cfg)


def save_config(cfg: dict) -> bool:
    """Persist configuration to ~/.ruk_hacker/config.json (mode 0600)."""
    global _CACHE
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, sort_keys=True)
        os.replace(tmp, CONFIG_FILE)
        try:
            os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        _CACHE = dict(cfg)
        return True
    except OSError:
        return False


def set_value(key: str, value) -> dict:
    cfg = load_config(reload=True)
    cfg[key] = value
    save_config(cfg)
    return cfg


def ensure_report_dir(cfg: dict = None) -> str:
    cfg = cfg or load_config()
    path = os.path.expanduser(cfg.get("report_dir") or REPORT_DIR)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        path = os.path.join(HOME_DIR, "ruk_reports")
        os.makedirs(path, exist_ok=True)
    return path


def data_path(filename: str) -> str:
    return os.path.join(DATA_DIR, filename)
