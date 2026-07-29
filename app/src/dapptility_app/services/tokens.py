from __future__ import annotations

import secrets


def new_report_token() -> str:
    return secrets.token_urlsafe(32)
