"""
Point d'entrée — client local
-------------------------------
Usage :
  python -m secure_tunnel.main \\
      --server wss://my-tunnel.onrender.com/tunnel \\
      --secret <secret> \\
      [--host 127.0.0.1] [--port 1080] [--log-level INFO]

Ou via variables d'environnement :
  TUNNEL_SECRET, TUNNEL_SERVER_URL, SOCKS5_HOST, SOCKS5_PORT, LOG_LEVEL
"""

import argparse
import asyncio
import logging
import os
import sys

from secure_tunnel.proxy.socks5 import Socks5Server
from secure_tunnel.client.tunnel_client import TunnelClient
from secure_tunnel.utils.logger import setup_logging
from secure_tunnel.utils.signals import register_shutdown
from secure_tunnel.utils.stats import tracker


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Secure Tunnel — proxy SOCKS5 chiffré via WebSocket",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--server",    default=os.environ.get("TUNNEL_SERVER_URL", ""),
                   help="URL WSS du serveur Render (ex: wss://my-app.onrender.com/tunnel)")
    p.add_argument("--secret",    default=os.environ.get("TUNNEL_SECRET", ""),
                   help="Secret partagé client/serveur")
    p.add_argument("--host",      default=os.environ.get("SOCKS5_HOST", "127.0.0.1"),
                   help="Hôte d'écoute SOCKS5 local")
    p.add_argument("--port",      default=int(os.environ.get("SOCKS5_PORT", "1080")),
                   type=int,      help="Port d'écoute SOCKS5 local")
    p.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                   choices=["DEBUG","INFO","WARNING","ERROR"],
                   help="Niveau de verbosité des logs")
    return p.parse_args()


async def _print_stats_loop(interval: int = 60):
    """Affiche les stats de trafic toutes les `interval` secondes."""
    logger = logging.getLogger("stats")
    while True:
        await asyncio.sleep(interval)
        logger.info(tracker.summary())


async def main():
    args   = parse_args()
    logger = setup_logging("main")
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Validation des arguments obligatoires
    errors = []
    if not args.server:
        errors.append("--server (ou TUNNEL_SERVER_URL) est obligatoire")
    if not args.secret:
        errors.append("--secret (ou TUNNEL_SECRET) est obligatoire")
    if errors:
        for e in errors:
            logger.error(e)
        sys.exit(1)

    secret = args.secret.encode()
    client = TunnelClient(server_url=args.server, secret=secret)
    proxy  = Socks5Server(host=args.host, port=args.port, tunnel_handler=client.handle)

    await proxy.start()

    banner = [
        "=" * 58,
        f"  Proxy SOCKS5 local  : socks5://{args.host}:{args.port}",
        f"  Tunnel vers         : {args.server}",
        "  Chiffrement         : ChaCha20-Poly1305 + HKDF-SHA256",
        "  Obfuscation         : padding aléatoire + jitter",
        "=" * 58,
        "  Exemples d'utilisation :",
        f"    curl --proxy socks5h://{args.host}:{args.port} https://ifconfig.me",
        f"    export ALL_PROXY=socks5://{args.host}:{args.port}",
        "=" * 58,
    ]
    for line in banner:
        logger.info(line)

    # Arrêt propre sur SIGINT/SIGTERM
    loop      = asyncio.get_running_loop()
    stop_evt  = asyncio.Event()
    register_shutdown(loop, stop_evt)

    # Stats périodiques
    stats_task = asyncio.create_task(_print_stats_loop(60))

    try:
        # Bloque jusqu'à signal d'arrêt
        done, _ = await asyncio.wait(
            [asyncio.create_task(stop_evt.wait()),
             asyncio.create_task(proxy.serve_forever())],
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        stats_task.cancel()
        await proxy.stop()
        logger.info("Tunnel arrêté. Statistiques finales :")
        logger.info(tracker.summary())


if __name__ == "__main__":
    asyncio.run(main())
