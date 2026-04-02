# 🔒 Secure Tunnel — SOCKS5 over Encrypted WebSocket

Proxy SOCKS5 local qui tunnelise tout le trafic via un WebSocket chiffré
vers un serveur hébergé sur **Render.com**. Zéro configuration réseau,
zéro VPS à gérer.

```
[Application]
     │  SOCKS5  (127.0.0.1:1080)
     ▼
[Client local Python]
     │  WSS + ChaCha20-Poly1305 + padding aléatoire + jitter
     ▼
[Render.com — TLS automatique]
     │  TCP sortant normal
     ▼
[Internet]
```

---

## 🛡️ Stack de sécurité

| Couche | Technologie | Rôle |
|---|---|---|
| Chiffrement | ChaCha20-Poly1305 | AEAD 256 bits, résistant aux timing attacks |
| Dérivation de clé | HKDF-SHA256 | Secret partagé → clé unique par session |
| Transport | WebSocket over TLS | Trafic identique à du HTTPS normal |
| Obfuscation taille | Padding aléatoire 16–256 B | Masque la taille réelle des messages |
| Obfuscation timing | Jitter 0.5–8 ms | Casse les patterns d'inter-paquets |

---

## 🚀 Déploiement rapide (≈ 10 min)

### 1. Pousser sur GitHub

```bash
git init && git add . && git commit -m "init"
git remote add origin https://github.com/<vous>/secure-tunnel.git
git push -u origin main
```

### 2. Déployer sur Render

1. [render.com](https://render.com) → **New Web Service** → connecter le repo
2. Render détecte `render.yaml` automatiquement
3. **Environment Variables** → ajouter :
   ```
   TUNNEL_SECRET = <secret_long_et_aléatoire>
   ```
4. **Deploy** — Render fournit une URL : `https://secure-tunnel-server.onrender.com`

> Le health check HTTP et le WebSocket tunnel tournent sur le même port.
> Render vérifie `GET /` → 200 OK. Les clients WebSocket se connectent
> sur la même URL avec header `Upgrade: websocket`.

### 3. Lancer le client local

```bash
pip install -r requirements.txt

python -m secure_tunnel.main \
  --server wss://secure-tunnel-server.onrender.com \
  --secret <le_même_secret>
```

Ou via variables d'environnement :

```bash
export TUNNEL_SECRET="mon_secret"
export TUNNEL_SERVER_URL="wss://secure-tunnel-server.onrender.com"
python -m secure_tunnel.main
```

Sortie attendue :
```
12:00:00 [INFO    ] main    ==========================================================
12:00:00 [INFO    ] main      Proxy SOCKS5 local  : socks5://127.0.0.1:1080
12:00:00 [INFO    ] main      Tunnel vers         : wss://secure-tunnel-server.onrender.com
12:00:00 [INFO    ] main      Chiffrement         : ChaCha20-Poly1305 + HKDF-SHA256
12:00:00 [INFO    ] main      Obfuscation         : padding aléatoire + jitter
12:00:00 [INFO    ] main    ==========================================================
```

### 4. Utiliser le proxy

**curl :**
```bash
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
```

**Firefox :** Paramètres → Réseau → Proxy manuel → SOCKS5 `127.0.0.1` port `1080`

**Système entier (Linux/macOS) :**
```bash
export ALL_PROXY=socks5://127.0.0.1:1080
```

---

## ⚙️ Options CLI

```
python -m secure_tunnel.main --help

  --server     URL WSS du serveur Render      [TUNNEL_SERVER_URL]
  --secret     Secret partagé client/serveur  [TUNNEL_SECRET]
  --host       Hôte d'écoute SOCKS5 local     [SOCKS5_HOST]     défaut: 127.0.0.1
  --port       Port d'écoute SOCKS5 local     [SOCKS5_PORT]     défaut: 1080
  --log-level  DEBUG / INFO / WARNING / ERROR [LOG_LEVEL]       défaut: INFO
```

---

## 🧪 Tests

```bash
pip install pytest pytest-asyncio
pytest secure_tunnel/tests/ -v --asyncio-mode=auto
```

```
15 passed in 0.22s ✅
```

---

## 📁 Structure du projet

```
secure_tunnel/
├── main.py                       # Point d'entrée client (CLI argparse)
├── render.yaml                   # Config déploiement Render
├── requirements.txt
├── README.md
│
├── crypto/
│   └── engine.py                 # ChaCha20-Poly1305 + HKDF-SHA256
│
├── obfuscation/
│   └── obfuscator.py             # Padding aléatoire + jitter temporel
│
├── proxy/
│   └── socks5.py                 # Serveur SOCKS5 local (RFC 1928)
│
├── client/
│   └── tunnel_client.py          # Client WebSocket chiffré
│
├── server/
│   └── tunnel_server.py          # Serveur Render (WS + health check)
│
├── utils/
│   ├── logger.py                 # Logger structuré configurable
│   ├── signals.py                # Graceful shutdown SIGINT/SIGTERM
│   ├── retry.py                  # Backoff exponentiel avec jitter
│   └── stats.py                  # Compteurs bytes ↑↓ + connexions
│
└── tests/
    ├── test_tunnel.py            # 12 tests unitaires (crypto + obfusc)
    └── test_integration.py       # 3 tests intégration (tunnel complet)
```
