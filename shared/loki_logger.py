"""
Shared Loki Log Handler (Bonus 5)
Pushes Python logs directly to Loki via HTTP API.
Works on all platforms (Windows Docker Desktop included).
"""
import os
import json
import time
import logging
import threading
import queue
from datetime import datetime

LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
LOKI_ENABLED = os.getenv("LOKI_ENABLED", "true").lower() == "true"


class LokiHandler(logging.Handler):
    """
    Python logging handler that pushes logs to Grafana Loki via HTTP.
    Batches logs and pushes every 2 seconds or when 50 entries accumulate.
    """

    def __init__(self, service_name: str, url: str = None, batch_size: int = 50, flush_interval: float = 2.0):
        super().__init__()
        self.service_name = service_name
        self.url = (url or LOKI_URL).rstrip("/") + "/loki/api/v1/push"
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def emit(self, record):
        try:
            log_entry = self.format(record)
            # Loki timestamps are in nanoseconds
            ts = str(int(time.time() * 1e9))
            self._queue.put((ts, log_entry, record.levelname.lower()))
        except Exception:
            self.handleError(record)

    def _worker(self):
        """Background thread that batches and pushes logs to Loki."""
        import urllib.request
        import urllib.error

        while not self._stop_event.is_set():
            entries = []
            try:
                # Collect entries up to batch_size or flush_interval
                deadline = time.time() + self.flush_interval
                while len(entries) < self.batch_size and time.time() < deadline:
                    try:
                        remaining = max(0.01, deadline - time.time())
                        entry = self._queue.get(timeout=remaining)
                        entries.append(entry)
                    except queue.Empty:
                        break

                if not entries:
                    continue

                # Group by level for Loki streams
                streams = {}
                for ts, line, level in entries:
                    key = level
                    if key not in streams:
                        streams[key] = {
                            "stream": {
                                "service": self.service_name,
                                "level": level,
                                "job": "oncall-platform",
                            },
                            "values": [],
                        }
                    streams[key]["values"].append([ts, line])

                payload = json.dumps({"streams": list(streams.values())})

                req = urllib.request.Request(
                    self.url,
                    data=payload.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        pass  # 204 = success
                except (urllib.error.URLError, urllib.error.HTTPError, OSError):
                    pass  # Silently drop on Loki unavailability

            except Exception:
                pass  # Never crash the worker thread

    def close(self):
        self._stop_event.set()
        self._thread.join(timeout=3)
        super().close()


def setup_loki_logging(service_name: str):
    """
    Add Loki handler to the root logger so ALL Python logs
    from this service are shipped to Grafana Loki.
    """
    if not LOKI_ENABLED:
        return

    try:
        handler = LokiHandler(service_name=service_name)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
        logging.getLogger().addHandler(handler)
        logging.getLogger(service_name).info(f"Loki logging enabled for {service_name}")
    except Exception as e:
        logging.getLogger().warning(f"Failed to setup Loki logging: {e}")
