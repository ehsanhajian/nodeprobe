from __future__ import annotations

import os
from pathlib import Path


class Settings:
    def __init__(self) -> None:
        self.database_url = os.environ.get(
            "DAPPILITY_DATABASE_URL",
            f"sqlite:///{Path(__file__).resolve().parents[3] / 'data' / 'dapptility.db'}",
        )
        self.admin_password = os.environ.get("DAPPILITY_ADMIN_PASSWORD", "changeme")
        self.secret_key = os.environ.get(
            "DAPPILITY_SECRET_KEY",
            "dev-secret-change-in-production",
        )
        self.report_base_url = os.environ.get(
            "DAPPILITY_REPORT_BASE_URL",
            "http://localhost:8000",
        )
        self.raw_evidence_retention_days = int(
            os.environ.get("DAPPILITY_RAW_RETENTION_DAYS", "30")
        )
        self.data_dir = Path(
            os.environ.get(
                "DAPPILITY_DATA_DIR",
                str(Path(__file__).resolve().parents[3] / "data"),
            )
        )
        self.reports_dir = self.data_dir / "reports"
        self.raw_dir = self.data_dir / "raw"
        self.chainlist_url = os.environ.get(
            "DAPPILITY_CHAINLIST_URL",
            "https://chainlist.org/rpcs.json",
        )
        self.discovery_enabled = os.environ.get("DAPPILITY_DISCOVERY_ENABLED", "true").lower() in {
            "1",
            "true",
            "yes",
        }
        self.discovery_hour_utc = int(os.environ.get("DAPPILITY_DISCOVERY_HOUR_UTC", "6"))
        self.discovery_auto_promote_score = int(
            os.environ.get("DAPPILITY_DISCOVERY_AUTO_PROMOTE_SCORE", "70")
        )


settings = Settings()

settings.data_dir.mkdir(parents=True, exist_ok=True)
settings.reports_dir.mkdir(parents=True, exist_ok=True)
settings.raw_dir.mkdir(parents=True, exist_ok=True)
