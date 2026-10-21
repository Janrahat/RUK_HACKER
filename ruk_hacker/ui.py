"""Terminal user interface helpers: colours, banner, tables, prompts."""

from __future__ import annotations

import os
import re
import shutil
import sys

from .config import APP_NAME, TAGLINE, VERSION

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"

ANSI_RE = re.compile(r"\033\[[0-9;]*m")

_COLOR_ENABLED = True

# Basic palette (256-colour safe for Termux)
COLORS = {
    "red": "\033[38;5;203m",
    "green": "\033[38;5;114m",
    "yellow": "\033[38;5;221m",
    "blue": "\033[38;5;75m",
    "magenta": "\033[38;5;176m",
    "cyan": "\033[38;5;80m",
    "white": "\033[38;5;255m",
    "gray": "\033[38;5;245m",
    "orange": "\033[38;5;215m",
    "purple": "\033[38;5;141m",
}

BANNER = r"""
 ____  _   _ _  __   _   _    _    ____ _  _______ ____
|  _ \| | | | |/ /  | | | |  / \  / ___| |/ / ____|  _ \
| |_) | | | | ' /   | |_| | / _ \| |   | ' /|  _| | |_) |
|  _ <| |_| | . \   |  _  |/ ___ \ |___| . \| |___|  _ <
|_| \_\\___/|_|\_\  |_| |_/_/   \_\____|_|\_\_____|_| \_\
"""

BANNER_GRADIENT = ["\033[38;5;213m", "\033[38;5;171m", "\033[38;5;135m",
                   "\033[38;5;99m", "\033[38;5;69m"]


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def set_color(enabled: bool) -> None:
    global _COLOR_ENABLED
    _COLOR_ENABLED = bool(enabled)


def color_enabled() -> bool:
    return _COLOR_ENABLED


def paint(text: str, color: str = None, bold: bool = False, dim: bool = False) -> str:
    if not _COLOR_ENABLED:
        return text
    prefix = ""
    if color and color in COLORS:
        prefix += COLORS[color]
    if bold:
        prefix += BOLD
    if dim:
        prefix += DIM
    if not prefix:
        return text
    return f"{prefix}{text}{RESET}"


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


def _ljust(text: str, width: int) -> str:
    pad = max(0, width - visible_len(text))
    return text + " " * pad


def _term_width(default: int = 78) -> int:
    try:
        return max(40, min(shutil.get_terminal_size((80, 24)).columns, 120))
    except Exception:
        return default


def banner(show_tagline: bool = True) -> None:
    """Print the coloured ASCII banner."""
    if not _COLOR_ENABLED:
        print(BANNER)
    else:
        for index, line in enumerate(BANNER.strip("\n").splitlines()):
            print(f"{BANNER_GRADIENT[index % len(BANNER_GRADIENT)]}{line}{RESET}")
    if show_tagline:
        tag = f" {TAGLINE} v{VERSION} "
        width = _term_width()
        side = max(0, (width - len(tag.strip()) - 2) // 2)
        line = "─" * side + tag + "─" * side
        print(paint(line, "gray", dim=True))
        print(paint("  ⚠  Legal use only: your own systems or authorised targets.", "yellow"))
        print()


def hr(char: str = "─", color: str = "gray") -> None:
    print(paint(char * _term_width(), color))


def header(title: str, icon: str = "»") -> None:
    width = _term_width()
    label = f" {icon} {title.strip().upper()} "
    side = max(0, (width - len(label)) // 2)
    print()
    print(paint("═" * side + label + "═" * side, "cyan", bold=True))


def section(title: str) -> None:
    print()
    print(paint(f"──[ {title} ]" + "─" * max(0, _term_width() - len(title) - 6), "blue", bold=True))


def success(msg: str) -> None:
    print(paint("  ✔ ", "green", bold=True) + msg)


def warn(msg: str) -> None:
    print(paint("  ⚠ ", "yellow", bold=True) + msg)


def error(msg: str) -> None:
    print(paint("  ✖ ", "red", bold=True) + paint(msg, "red"))


def info(msg: str) -> None:
    print(paint("  ℹ ", "blue") + msg)


def bullet(msg: str, color: str = "gray") -> None:
    print(paint("  • ", color) + msg)


def kv_table(data: dict, title: str = None, key_width: int = 22) -> None:
    """Print a two-column key/value table."""
    if title:
        section(title)
    items = [(str(k), _stringify(v)) for k, v in data.items()]
    if not items:
        print(paint("  (no data)", "gray", dim=True))
        return
    width = max([key_width] + [visible_len(k) for k, _ in items])
    top = "  ┌" + "─" * (width + 2) + "┬" + "─" * (min(_term_width() - width - 6, 60)) + "┐"
    print(paint(top, "gray", dim=True))
    for key, value in items:
        print(paint("  │ ", "gray", dim=True) + paint(_ljust(key, width), "white")
              + paint(" │ ", "gray", dim=True) + value)
    bottom = "  └" + "─" * (width + 2) + "┴" + "─" * (min(_term_width() - width - 6, 60)) + "┘"
    print(paint(bottom, "gray", dim=True))


def table(headers, rows, title: str = None, max_col: int = 46) -> None:
    """Print a simple bordered table."""
    if title:
        section(title)
    rows = [[_stringify(cell) for cell in row] for row in rows]
    if not rows:
        print(paint("  (no results)", "gray", dim=True))
        return
    widths = [visible_len(str(h)) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            if idx < len(widths):
                widths[idx] = max(widths[idx], min(visible_len(cell), max_col))
    sep = "  ├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    top = "  ┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    bot = "  └" + "┴".join("─" * (w + 2) for w in widths) + "┘"
    print(paint(top, "gray", dim=True))
    print(paint("  │ ", "gray", dim=True) + paint(" │ ".join(_ljust(str(h), widths[i]) for i, h in enumerate(headers)), "cyan", bold=True)
          + paint(" │", "gray", dim=True))
    print(paint(sep, "gray", dim=True))
    for row in rows:
        cells = []
        for idx, cell in enumerate(row):
            if idx >= len(widths):
                continue
            if visible_len(cell) > max_col:
                cell = cell[: max_col - 1] + "…"
            cells.append(_ljust(cell, widths[idx]))
        print(paint("  │ ", "gray", dim=True) + paint(" │ ", "gray", dim=True).join(cells)
              + paint(" │", "gray", dim=True))
    print(paint(bot, "gray", dim=True))


def progress(done: int, total: int, label: str = "") -> None:
    """Render an in-place progress line (no newline)."""
    if total <= 0:
        return
    pct = int(done * 100 / total)
    bar_len = 26
    filled = int(bar_len * done / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    text = f"\r  {paint(bar, 'cyan')} {pct:3d}%  {done}/{total}  {label[:24]}"
    sys.stdout.write(text + " " * 6)
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


def prompt(label: str, default: str = "") -> str:
    """Ask for a text value."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(paint(f"  ? {label}{suffix}: ", "cyan", bold=True)).strip()
    except EOFError:
        return default
    return value or default


def confirm(label: str, default: bool = False) -> bool:
    """Ask a yes/no question."""
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(paint(f"  ? {label} [{hint}]: ", "cyan", bold=True)).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes", "h", "haan", "ہاں")


def _stringify(value) -> str:
    if value is None:
        return paint("—", "gray", dim=True)
    if isinstance(value, bool):
        return paint("yes", "green") if value else paint("no", "gray")
    if isinstance(value, float):
        return f"{value:.2f}"
    if isinstance(value, (list, tuple)):
        return ", ".join(_stringify(v) for v in value) if value else paint("—", "gray", dim=True)
    text = str(value)
    if len(text) > 70:
        return text[:67] + "…"
    return text


def footer() -> None:
    print()
    print(paint(f"  {APP_NAME} v{VERSION} ─ ", "gray", dim=True)
          + paint("End of results", "gray", dim=True))
    print()
