#!/usr/bin/env sh
#
# Evaluate the CryptoServe policy for a given context via the API.
#
# Reads CRYPTOSERVE_API_URL and CRYPTOSERVE_API_KEY from the environment.
# Both must be configured as masked + protected CI/CD variables -- never
# pass them on the command line. Exits 0 on policy "allowed", 1 otherwise.

set -eu

: "${CRYPTOSERVE_API_URL:?CRYPTOSERVE_API_URL must be set in CI/CD variables}"
: "${CRYPTOSERVE_API_KEY:?CRYPTOSERVE_API_KEY must be set in CI/CD variables}"

echo "Evaluating policies via API..."

response=$(
  curl -fsS -X POST \
    "${CRYPTOSERVE_API_URL}/api/policies/evaluate" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${CRYPTOSERVE_API_KEY}" \
    -d '{
      "algorithm": "AES-256-GCM",
      "context_name": "user-pii",
      "pii": true,
      "frameworks": ["GDPR", "CCPA"]
    }'
)

allowed=$(printf '%s' "$response" | grep -o '"allowed":[^,]*' | cut -d: -f2 | tr -d ' "')

if [ "$allowed" = "false" ]; then
  echo "ERROR: Policy violation for PII context"
  printf '%s\n' "$response"
  exit 1
fi

echo "All policy checks passed!"
