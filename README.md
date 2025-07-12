# Augesty Token‑Authenticated Docker Registry

This repository bundles:

1. **`augesty`** – a Rust‑based token server (in `backend/`)
2. A Docker Compose stack:
   - `augesty` service exposing port **8080**
   - Official Docker Registry v2 on port **5000** with JWT token‑auth
3. A GitHub Action (`action.yml`) for exchanging a GitHub token for an Augesty service‑account token

## Warning

This is work in progress. Its still missing:

- HTTPS in backend
- a frontend
- automated testing

The security of this is neither tested nor guaranteed!
It is a fun side project for learning purposes!

---

## Contents

```
.
├── action.yml         # GitHub Action: exchange GH token ↔ Augesty token
├── backend/           # Rust token‑server code
├── docker-compose.yml # Compose stack wiring augesty + registry
└── README.md          # (this file)
```

---

## Getting Started

### 1. Build & run locally

```bash
# Build your token server image
cd backend
docker build -t augesty:latest .

# From repo root, bring up the stack
docker-compose up -d
```

- **Augesty** is reachable at `http://localhost:8080`
- **Registry** is reachable at `http://localhost:5000`  
  – token auth is configured via the shared `/config/augesty/jwt.pub` pubkey

---

### 2. Directory & Volumes

- **`augesty-config` volume**  
  - Mounted read/write at `/config` in the augesty container  
    - Stores its SQLite DB at `/config/augesty.db`  
    - Populates `/config/augesty/jwt.pub` (public key)
  - Mounted read‑only at `/config/augesty` in the registry container  
    - Used for JWT verification
- **`registry-data` volume**  
  - Persists all registry blobs & manifests under `/var/lib/registry`

---

### 3. Environment Variables

#### augesty service

| Variable       | Description                                | Example                        |
| -------------- | ------------------------------------------ | ------------------------------ |
| `DATABASE_PATH`| Path to SQLite DB in container             | `/config/augesty.db`           |
| `DOCKER_URL`   | Base URL of your registry                  | `registry.example.com`         |
| `OWN_URL`      | Public URL for callback/redirect if used   | `augesty.example.com`          |

#### registry service

| Variable                             | Description                                     | Example                                         |
| ------------------------------------ | ----------------------------------------------- | ----------------------------------------------- |
| `REGISTRY_AUTH`                      | Enable token auth (`token`)                     | `token`                                         |
| `REGISTRY_AUTH_TOKEN_REALM`          | Token‑server’s issuer endpoint                  | `https://augesty.example.com/api/token`         |
| `REGISTRY_AUTH_TOKEN_SERVICE`        | Service name expected in the token              | `registry`                                      |
| `REGISTRY_AUTH_TOKEN_ISSUER`         | Token issuer                                    | `augesty.example.com`                           |
| `REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE` | Path to public JWT key for verification (RO)    | `/config/augesty/jwt.pub`                       |

---

## `backend/` (Rust)

- Contains the source for your `augesty` token server
- Uses SQLite for persistence (`augesty.db`)
- Exposes an HTTP API on port 8080
- Generates and signs JWTs for Docker Registry auth
- exposes a swaggerui at /api/swagger

---

### Usage in your workflow

```yaml
jobs:
  get-token:
    runs-on: ubuntu-latest
    permissions:
      contents: "read"
      id-token: "write"
    steps:
      - uses: actions/checkout@v3

      - name: Obtain Augesty token
        uses: meixnerlu/augesty@v1
        with:
          service_account: my-service-account
          service_url: https://augesty.example.com/api/token

      - name: Use token
        run: |
          echo "Token is ${{ steps.get-token.outputs.accesstoken }}"
```

---

## SSL / Reverse‑Proxy

We recommend terminating TLS at your front‑door (e.g. NGINX, Traefik, Caddy). Simply reverse‑proxy:

- `https://registry.example.com` → `http://localhost:5000`
- `https://augesty.example.com` → `http://localhost:8080`

---

## License

MIT
