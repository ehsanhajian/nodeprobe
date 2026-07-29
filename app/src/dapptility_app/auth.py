from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from dapptility_app.config import settings

security = HTTPBasic()


def verify_admin(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> str:
    correct = secrets.compare_digest(
        credentials.password.encode(),
        settings.admin_password.encode(),
    )
    if not correct or credentials.username != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
