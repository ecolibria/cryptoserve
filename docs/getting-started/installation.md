# Installation

This guide covers multiple ways to install and run CryptoServe.

## Docker (Recommended)

The fastest way to get started is with Docker Compose.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 20.10+
- [Docker Compose](https://docs.docker.com/compose/install/) v2.0+

### Steps

```bash
# Clone the repository
git clone https://github.com/ecolibria/crypto-serve.git
cd crypto-serve

# Copy environment template
cp .env.example .env

# Edit .env with your settings (see Configuration)
# At minimum, set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET

# Start all services
docker compose up -d
```

### Verify Installation

```bash
# Check service health
docker compose ps

# View logs
docker compose logs -f backend
```

The services will be available at:

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3003 |
| API | http://localhost:8003 |
| API Docs | http://localhost:8003/docs |

---

## Local Development

For development or customization, run each component locally.

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm or yarn

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp ../.env.example .env

# Run database migrations (auto-creates SQLite DB)
python -c "from app.database import init_db; import asyncio; asyncio.run(init_db())"

# Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8003
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Create environment file
cat > .env.local << EOF
NEXT_PUBLIC_API_URL=http://localhost:8003
EOF

# Start development server
npm run dev
```

### SDK Development

```bash
cd sdk/python

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest -v
```

---

## Production Deployment

For production environments, we recommend:

### Kubernetes

A Helm chart is available:

```bash
helm repo add cryptoserve https://ecolibria.github.io/crypto-serve/helm
helm install cryptoserve cryptoserve/cryptoserve \
  --set github.clientId=$GITHUB_CLIENT_ID \
  --set github.clientSecret=$GITHUB_CLIENT_SECRET \
  --set masterKey=$MASTER_KEY
```

### Docker Compose (Production)

Use the production compose file:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

This adds:

- Nginx reverse proxy with TLS
- PostgreSQL instead of SQLite
- Health checks and restart policies
- Resource limits

### Cloud Platforms

| Platform | Guide |
|----------|-------|
| AWS ECS | [Deployment Guide](../guides/production.md#aws-ecs) |
| Google Cloud Run | [Deployment Guide](../guides/production.md#cloud-run) |
| Azure Container Apps | [Deployment Guide](../guides/production.md#azure) |

---

## Post-Quantum Support

To enable post-quantum cryptography, install liboqs:

### Ubuntu/Debian

```bash
# Install build dependencies
sudo apt-get install cmake gcc ninja-build libssl-dev

# Install liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig

# Install Python bindings
pip install liboqs-python
```

### macOS

```bash
brew install liboqs
pip install liboqs-python
```

### Docker (Included)

The Docker image includes liboqs pre-installed.

---

## Verification

After installation, verify everything is working:

```bash
# Check API health
curl http://localhost:8003/health

# Expected response:
# {"status":"healthy","version":"1.0.0"}
```

```bash
# Check available contexts
curl http://localhost:8003/api/contexts

# Expected: List of default contexts
```

---

## Next Steps

- [Configure OAuth and environment](configuration.md)
- [Complete the Quick Start](quickstart.md)
- [Learn the architecture](../concepts/architecture.md)

## Troubleshooting

??? question "Port already in use"

    Change the port in `docker-compose.yml` or use a different port:
    ```bash
    uvicorn app.main:app --port 8002
    ```

??? question "Database connection errors"

    Ensure PostgreSQL is running and credentials are correct:
    ```bash
    docker compose logs db
    ```

??? question "OAuth callback errors"

    Verify your GitHub OAuth app callback URL matches exactly:
    ```
    http://localhost:8003/auth/github/callback
    ```

??? question "liboqs import errors"

    Ensure liboqs is installed and `LD_LIBRARY_PATH` includes `/usr/local/lib`:
    ```bash
    export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
    ```
