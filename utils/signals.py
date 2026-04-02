"""
Gestion propre des signaux OS
------------------------------
Intercepte SIGINT / SIGTERM pour fermer proprement le serveur
SOCKS5 et les connexions WebSocket en cours avant de quitter.
"""

import asyncio
import logging
import signal

logger = logging.getLogger("utils.signals")


def register_shutdown(loop: asyncio.AbstractEventLoop, stop_event: asyncio.Event):
    """
    Enregistre SIGINT et SIGTERM sur la boucle asyncio fournie.
    Quand l'un de ces signaux est reçu, `stop_event` est activé.

    Usage :
        stop = asyncio.Event()
        register_shutdown(asyncio.get_event_loop(), stop)
        await stop.wait()   # bloque jusqu'au signal
    """
    def _handler(sig):
        logger.info(f"Signal {sig.name} reçu — arrêt en cours…")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handler, sig)

    logger.debug("Gestionnaires SIGINT/SIGTERM enregistrés.")
