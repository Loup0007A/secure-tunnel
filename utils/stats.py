"""
Statistiques de session
------------------------
Comptabilise en temps réel :
  - bytes envoyés / reçus
  - nombre de connexions actives / totales
  - erreurs

Accessible via get_stats() pour affichage ou monitoring.
"""

import time
import threading
from dataclasses import dataclass, field


@dataclass
class Stats:
    bytes_sent:      int = 0
    bytes_received:  int = 0
    connections_total:  int = 0
    connections_active: int = 0
    errors:          int = 0
    started_at:      float = field(default_factory=time.time)

    def uptime(self) -> float:
        return time.time() - self.started_at

    def summary(self) -> str:
        up = self.uptime()
        h, r = divmod(int(up), 3600)
        m, s = divmod(r, 60)
        return (
            f"Uptime {h:02d}:{m:02d}:{s:02d} | "
            f"Connexions : {self.connections_active} actives / {self.connections_total} total | "
            f"↑ {_human(self.bytes_sent)}  ↓ {_human(self.bytes_received)} | "
            f"Erreurs : {self.errors}"
        )


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class StatsTracker:
    """Thread-safe wrapper autour de Stats."""

    def __init__(self):
        self._stats = Stats()
        self._lock  = threading.Lock()

    def connection_opened(self):
        with self._lock:
            self._stats.connections_total  += 1
            self._stats.connections_active += 1

    def connection_closed(self):
        with self._lock:
            self._stats.connections_active = max(0, self._stats.connections_active - 1)

    def add_sent(self, n: int):
        with self._lock:
            self._stats.bytes_sent += n

    def add_received(self, n: int):
        with self._lock:
            self._stats.bytes_received += n

    def add_error(self):
        with self._lock:
            self._stats.errors += 1

    def get(self) -> Stats:
        with self._lock:
            # Retourne une copie
            return Stats(
                bytes_sent        = self._stats.bytes_sent,
                bytes_received    = self._stats.bytes_received,
                connections_total = self._stats.connections_total,
                connections_active= self._stats.connections_active,
                errors            = self._stats.errors,
                started_at        = self._stats.started_at,
            )

    def summary(self) -> str:
        return self.get().summary()


# Instance globale partagée entre client et proxy
tracker = StatsTracker()
