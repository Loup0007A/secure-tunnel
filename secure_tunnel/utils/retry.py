"""
Reconnexion automatique avec backoff exponentiel
--------------------------------------------------
Si la connexion WebSocket vers Render est perdue (redémarrage du service,
coupure réseau, timeout idle), le client tente de se reconnecter
automatiquement avec un délai croissant pour éviter de spammer.

Stratégie :
  tentative 1 →  1s
  tentative 2 →  2s
  tentative 3 →  4s
  ...
  tentative N →  min(base * 2^n, max_delay) + jitter aléatoire
"""

import asyncio
import logging
import random

logger = logging.getLogger("utils.retry")


class RetryPolicy:
    def __init__(
        self,
        base_delay: float  = 1.0,   # délai initial en secondes
        max_delay:  float  = 60.0,  # plafond
        max_tries:  int    = 0,     # 0 = infini
        jitter:     bool   = True,  # ajouter un bruit aléatoire
    ):
        self.base_delay = base_delay
        self.max_delay  = max_delay
        self.max_tries  = max_tries
        self.jitter     = jitter

    def delay(self, attempt: int) -> float:
        """Calcule le délai pour la tentative N (commence à 1)."""
        d = min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
        if self.jitter:
            d *= (0.75 + random.random() * 0.5)   # ±25 %
        return d

    def exhausted(self, attempt: int) -> bool:
        return self.max_tries > 0 and attempt > self.max_tries


async def with_retry(coro_factory, policy: RetryPolicy | None = None, label="tâche"):
    """
    Exécute `coro_factory()` et relance en cas d'exception,
    selon la RetryPolicy fournie.

    coro_factory : callable sans argument qui retourne une coroutine
    policy       : RetryPolicy (défaut = backoff infini)
    label        : nom affiché dans les logs

    Exemple :
        await with_retry(lambda: client.connect(), label="tunnel WS")
    """
    policy  = policy or RetryPolicy()
    attempt = 0

    while True:
        attempt += 1
        try:
            logger.debug(f"[RETRY] {label} — tentative {attempt}")
            await coro_factory()
            attempt = 0   # succès → reset compteur
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if policy.exhausted(attempt):
                logger.error(f"[RETRY] {label} — abandon après {attempt} tentatives: {exc}")
                raise

            delay = policy.delay(attempt)
            logger.warning(
                f"[RETRY] {label} — erreur (tentative {attempt}): {exc}. "
                f"Reconnexion dans {delay:.1f}s…"
            )
            await asyncio.sleep(delay)
