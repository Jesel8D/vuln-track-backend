"""Persist the RC2.2 live NVD process deadline across launcher/operator switches."""

import json
import time

from app.integrations.nvd import Quota


class CatalogQuota(Quota):
    def __init__(self, path, save):
        super().__init__()
        self.path = path
        self.save = save
        if path.exists():
            data = json.loads(path.read_text())
            now = time.time()
            self.next_call = self.clock() + max(0, data["not_before"] - now)
            self.cooldown = self.clock() + max(0, data.get("cooldown", 0) - now)

    def persist(self):
        with self.lock:
            now = time.time()
            observed = self.clock()
            self.save(
                self.path,
                {
                    "not_before": now + max(0, self.next_call - observed),
                    "cooldown": now + max(0, self.cooldown - observed),
                },
            )

    def reserve(self):
        super().reserve()
        self.persist()

    def backoff(self, retry_after=None):
        super().backoff(retry_after)
        self.persist()
