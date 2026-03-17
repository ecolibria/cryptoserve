# ============================================================================
# Stage 1: Builder - compile liboqs and install Python dependencies
# ============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs for post-quantum cryptography
RUN git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cd /tmp/liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    ninja && ninja install && \
    rm -rf /tmp/liboqs

# Install Python dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
COPY requirements-pqc.txt .
RUN pip install --no-cache-dir -r requirements.txt -r requirements-pqc.txt

# ============================================================================
# Stage 2: Runtime - minimal image with only runtime dependencies
# ============================================================================
FROM python:3.12-slim

WORKDIR /app

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs shared libraries from builder
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

# Copy Python virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Ensure liboqs is found at runtime
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib

# Create non-root user
RUN groupadd -r cryptoserve && useradd -r -g cryptoserve -d /app -s /sbin/nologin cryptoserve

# Copy application code
COPY --chown=cryptoserve:cryptoserve . .

# Switch to non-root user
USER cryptoserve

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8003/health || exit 1

# Run server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
