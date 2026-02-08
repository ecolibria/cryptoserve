#!/bin/sh
set -e

# Ensure data directory exists for SQLite persistence
mkdir -p /data

# Set DATABASE_URL to use the persistent volume if not already set
export DATABASE_URL="${DATABASE_URL:-sqlite+aiosqlite:///data/cryptoserve.db}"

echo "============================================"
echo "  CryptoServe All-in-One"
echo "============================================"
echo "  API:       http://localhost:8003"
echo "  Dashboard: http://localhost:3000"
echo "  Health:    http://localhost:8003/health"
echo "  Data:      /data/cryptoserve.db"
echo "============================================"

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/cryptoserve.conf
