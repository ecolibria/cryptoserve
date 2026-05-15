# Contributing to CryptoServe

Thank you for your interest in contributing to CryptoServe!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/cryptoserve.git`
3. Create a branch: `git checkout -b feature/your-feature`

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker and Docker Compose
- PostgreSQL (or use Docker)

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start PostgreSQL
docker compose up -d postgres

# Run server
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### SDK

```bash
cd sdk/python
pip install -e .
```

## Code Style

### Python

- Use type hints
- Format with `black`
- Lint with `ruff`
- Sort imports with `isort`

### TypeScript

- Use strict mode
- Format with Prettier
- Lint with ESLint

### Prose

- No em dashes (Unicode U+2014) in any tracked markdown file. Use a period, semicolon, colon, parentheses, or comma instead. The `Style Check` CI job enforces this.
- En dashes (U+2013) are fine for numeric ranges (e.g., `80` to `120`).

## Testing

### Backend Tests

```bash
cd backend
pytest
```

### Frontend Tests

```bash
cd frontend
npm test
```

## Pull Request Process

1. Ensure tests pass
2. Update documentation if needed
3. Add a clear description of changes
4. Reference any related issues

## Security

If you discover a security vulnerability, please do NOT open a public issue. Instead, email security@example.com with details.

## Code of Conduct

Be respectful and inclusive. We welcome contributors of all backgrounds.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
