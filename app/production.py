"""Production entry point: one process, private settings, optional explicit live NVD."""

import json
import os
from pathlib import Path

from app.core.config import Settings, validate_origin
from app.main import create_app as application


def create_app():
    path = Path("/run/runtime/api-settings.json")
    info = path.stat()
    if (
        path.is_symlink()
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_size > 8192
    ):
        raise ValueError("Production settings require an owner-only private file")
    values = json.loads(path.read_text())
    settings = Settings(_env_file=None, **values)
    if settings.environment != "production":
        raise ValueError("Production entry point requires production environment")
    if settings.nvd_mode == "disabled":
        if settings.cve_live_enabled or settings.cve_worker_enabled:
            raise ValueError("Disabled NVD mode requires external CVE and workers disabled")
    elif settings.nvd_mode == "live":
        if not settings.cve_live_enabled:
            raise ValueError("Live NVD mode requires cve_live_enabled=true")
    else:
        raise ValueError("Production supports only disabled or explicit live NVD mode")
    if len(settings.cors_origins) != 1:
        raise ValueError("Production requires exactly one HTTPS frontend origin")
    validate_origin(settings.cors_origins[0])
    return application(settings)
