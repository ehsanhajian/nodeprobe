"""Global emergency kill switch for scans."""

from __future__ import annotations

import os
import threading
from pathlib import Path

DEFAULT_KILL_FILE = Path(os.environ.get("DAPPILITY_KILL_SWITCH", "/tmp/dapptility-scan-kill"))

_lock = threading.Lock()
_forced = False


class KillSwitchActive(RuntimeError):
    """Raised when the global kill switch is active."""


def force_kill(active: bool = True) -> None:
    global _forced
    with _lock:
        _forced = active


def reset() -> None:
    global _forced
    with _lock:
        _forced = False
        if DEFAULT_KILL_FILE.exists():
            try:
                DEFAULT_KILL_FILE.unlink()
            except OSError:
                pass


def is_active(kill_file: Path | None = None) -> bool:
    path = kill_file or DEFAULT_KILL_FILE
    with _lock:
        if _forced:
            return True
        return path.exists()


def check(kill_file: Path | None = None) -> None:
    if is_active(kill_file):
        raise KillSwitchActive("Global scan kill switch is active")
