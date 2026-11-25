"""Production entry point: one process, private settings, external CVE disabled."""

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
    if (
        settings.environment != "production"
        or settings.nvd_mode != "disabled"
        or settings.cve_worker_enabled
    ):
        raise ValueError("Production requires external CVE and workers disabled")
    if len(settings.cors_origins) != 1:
        raise ValueError("Production requires exactly one HTTPS frontend origin")
    validate_origin(settings.cors_origins[0])
    return application(settings)
