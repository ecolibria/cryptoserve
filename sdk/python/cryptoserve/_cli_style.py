"""Professional CLI styling for CryptoServe.

Provides consistent, enterprise-grade terminal output styling.
"""

import os
import sys

# Check if terminal supports colors
def _supports_color() -> bool:
    """Check if the terminal supports ANSI colors."""
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return os.getenv("TERM") == "xterm" or os.getenv("ANSICON")
    return True


COLORS_ENABLED = _supports_color()


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""

    # Reset
    RESET = "\033[0m" if COLORS_ENABLED else ""

    # Regular colors
    BLACK = "\033[30m" if COLORS_ENABLED else ""
    RED = "\033[31m" if COLORS_ENABLED else ""
    GREEN = "\033[32m" if COLORS_ENABLED else ""
    YELLOW = "\033[33m" if COLORS_ENABLED else ""
    BLUE = "\033[34m" if COLORS_ENABLED else ""
    MAGENTA = "\033[35m" if COLORS_ENABLED else ""
    CYAN = "\033[36m" if COLORS_ENABLED else ""
    WHITE = "\033[37m" if COLORS_ENABLED else ""

    # Bright colors
    BRIGHT_BLACK = "\033[90m" if COLORS_ENABLED else ""
    BRIGHT_RED = "\033[91m" if COLORS_ENABLED else ""
    BRIGHT_GREEN = "\033[92m" if COLORS_ENABLED else ""
    BRIGHT_YELLOW = "\033[93m" if COLORS_ENABLED else ""
    BRIGHT_BLUE = "\033[94m" if COLORS_ENABLED else ""
    BRIGHT_MAGENTA = "\033[95m" if COLORS_ENABLED else ""
    BRIGHT_CYAN = "\033[96m" if COLORS_ENABLED else ""
    BRIGHT_WHITE = "\033[97m" if COLORS_ENABLED else ""

    # Styles
    BOLD = "\033[1m" if COLORS_ENABLED else ""
    DIM = "\033[2m" if COLORS_ENABLED else ""
    ITALIC = "\033[3m" if COLORS_ENABLED else ""
    UNDERLINE = "\033[4m" if COLORS_ENABLED else ""


# Semantic color aliases
class Style:
    """Semantic style aliases."""

    # Status colors
    SUCCESS = Colors.BRIGHT_GREEN
    ERROR = Colors.BRIGHT_RED
    WARNING = Colors.BRIGHT_YELLOW
    INFO = Colors.BRIGHT_BLUE

    # UI elements
    HEADER = Colors.BRIGHT_CYAN + Colors.BOLD
    SUBHEADER = Colors.CYAN
    LABEL = Colors.BRIGHT_WHITE + Colors.BOLD
    VALUE = Colors.WHITE
    DIM = Colors.BRIGHT_BLACK
    ACCENT = Colors.BRIGHT_MAGENTA

    # Reset
    RESET = Colors.RESET


# Unicode box-drawing characters
class Box:
    """Unicode box-drawing characters for tables and borders."""

    # Corners
    TOP_LEFT = "╭"
    TOP_RIGHT = "╮"
    BOTTOM_LEFT = "╰"
    BOTTOM_RIGHT = "╯"

    # Lines
    HORIZONTAL = "─"
    VERTICAL = "│"

    # T-junctions
    T_DOWN = "┬"
    T_UP = "┴"
    T_RIGHT = "├"
    T_LEFT = "┤"
    CROSS = "┼"

    # Double lines (for emphasis)
    DOUBLE_HORIZONTAL = "═"
    DOUBLE_VERTICAL = "║"


# Status icons (text-based for professional appearance)
class Icons:
    """Unicode icons for status indicators."""

    SUCCESS = "+"
    ERROR = "x"
    WARNING = "!"
    INFO = "*"
    PENDING = "o"
    IN_PROGRESS = "-"
    ARROW_RIGHT = ">"
    ARROW_LEFT = "<"
    BULLET = "-"
    STAR = "*"
    LOCK = "[locked]"
    UNLOCK = "[unlocked]"
    KEY = "[key]"
    SHIELD = "[secure]"
    CHECK = "[x]"
    ROCKET = "[deploy]"
    CLOCK = "[time]"
    LINK = "[link]"


def header(text: str, width: int = 60) -> str:
    """Create a styled header box."""
    lines = []
    lines.append(f"{Style.HEADER}{Box.TOP_LEFT}{Box.HORIZONTAL * (width - 2)}{Box.TOP_RIGHT}{Style.RESET}")
    lines.append(f"{Style.HEADER}{Box.VERTICAL}{Style.RESET} {text.center(width - 4)} {Style.HEADER}{Box.VERTICAL}{Style.RESET}")
    lines.append(f"{Style.HEADER}{Box.BOTTOM_LEFT}{Box.HORIZONTAL * (width - 2)}{Box.BOTTOM_RIGHT}{Style.RESET}")
    return "\n".join(lines)


def subheader(text: str, width: int = 60) -> str:
    """Create a styled subheader."""
    line = Box.HORIZONTAL * width
    return f"\n{Style.SUBHEADER}{line}\n  {text}\n{line}{Style.RESET}"


def section(title: str) -> str:
    """Create a section header."""
    return f"\n{Style.LABEL}{title}{Style.RESET}"


def success(text: str) -> str:
    """Format success message."""
    return f"{Style.SUCCESS}{Icons.SUCCESS}{Style.RESET} {text}"


def error(text: str) -> str:
    """Format error message."""
    return f"{Style.ERROR}{Icons.ERROR}{Style.RESET} {text}"


def warning(text: str) -> str:
    """Format warning message."""
    return f"{Style.WARNING}{Icons.WARNING}{Style.RESET}  {text}"


def info(text: str) -> str:
    """Format info message."""
    return f"{Style.INFO}{Icons.INFO}{Style.RESET}  {text}"


def dim(text: str) -> str:
    """Format dimmed/secondary text."""
    return f"{Style.DIM}{text}{Style.RESET}"


def bold(text: str) -> str:
    """Format bold text."""
    return f"{Colors.BOLD}{text}{Style.RESET}"


def label_value(label: str, value: str, label_width: int = 20) -> str:
    """Format a label: value pair."""
    return f"  {Style.LABEL}{label.ljust(label_width)}{Style.RESET} {Style.VALUE}{value}{Style.RESET}"


def table_row(columns: list[str], widths: list[int]) -> str:
    """Format a table row."""
    parts = []
    for col, width in zip(columns, widths):
        parts.append(str(col).ljust(width)[:width])
    return f"  {' '.join(parts)}"


def table_header(columns: list[str], widths: list[int]) -> str:
    """Format a table header with underline."""
    header_line = table_row(columns, widths)
    underline = "  " + " ".join(Box.HORIZONTAL * w for w in widths)
    return f"{Style.LABEL}{header_line}{Style.RESET}\n{Style.DIM}{underline}{Style.RESET}"


def progress_bar(current: int, total: int, width: int = 30, show_percent: bool = True) -> str:
    """Create a progress bar."""
    if total == 0:
        percent = 100
    else:
        percent = int((current / total) * 100)

    filled = int((current / max(total, 1)) * width)
    empty = width - filled

    bar = "█" * filled + "░" * empty

    if percent >= 80:
        color = Style.SUCCESS
    elif percent >= 50:
        color = Style.WARNING
    else:
        color = Style.ERROR

    if show_percent:
        return f"{color}{bar}{Style.RESET} {percent}%"
    else:
        return f"{color}{bar}{Style.RESET}"


def status_badge(status: str) -> str:
    """Create a status badge."""
    status_lower = status.lower()
    if status_lower in ("ready", "active", "success", "healthy", "ok"):
        return f"{Style.SUCCESS}● {status}{Style.RESET}"
    elif status_lower in ("pending", "waiting", "in_progress"):
        return f"{Style.WARNING}○ {status}{Style.RESET}"
    elif status_lower in ("error", "failed", "blocked"):
        return f"{Style.ERROR}● {status}{Style.RESET}"
    else:
        return f"{Style.DIM}○ {status}{Style.RESET}"


def divider(width: int = 60, char: str = "─") -> str:
    """Create a horizontal divider."""
    return f"{Style.DIM}{char * width}{Style.RESET}"


def indent(text: str, spaces: int = 2) -> str:
    """Indent text by specified spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.split("\n"))


def code_block(code: str, language: str = "") -> str:
    """Format a code block."""
    lines = code.strip().split("\n")
    formatted = []
    formatted.append(f"{Style.DIM}┌{'─' * 58}┐{Style.RESET}")
    for line in lines:
        formatted.append(f"{Style.DIM}│{Style.RESET} {Style.ACCENT}{line.ljust(56)}{Style.RESET} {Style.DIM}│{Style.RESET}")
    formatted.append(f"{Style.DIM}└{'─' * 58}┘{Style.RESET}")
    return "\n".join(formatted)


def brand_header() -> str:
    """Create the CryptoServe brand header."""
    return f"""
{Style.HEADER}╭────────────────────────────────────────────────────────╮
│                                                        │
│   {Colors.BRIGHT_WHITE}CRYPTOSERVE{Style.HEADER}                                        │
│   {Style.DIM}Enterprise Cryptography Platform{Style.HEADER}                    │
│                                                        │
╰────────────────────────────────────────────────────────╯{Style.RESET}
"""


def compact_header(command: str = "") -> str:
    """Create a compact header for commands."""
    if command:
        return f"\n{Style.HEADER}CRYPTOSERVE{Style.RESET} {Style.DIM}›{Style.RESET} {Style.LABEL}{command}{Style.RESET}\n"
    return f"\n{Style.HEADER}CRYPTOSERVE{Style.RESET}\n"
