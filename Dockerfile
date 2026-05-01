# Multi-stage Docker build for secure-term-chat
FROM python:3.12-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.12-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash securechat
USER securechat

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set application metadata
LABEL org.opencontainers.image.title="secure-term-chat"
LABEL org.opencontainers.image.description="Anonymous E2EE encrypted terminal chat with TLS support"
LABEL org.opencontainers.image.vendor="Gzeu"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="${VERSION:-latest}"
LABEL org.opencontainers.image.revision="${VCS_REF:-unknown}"
LABEL org.opencontainers.image.created="${BUILD_DATE:-unknown}"

# Create application directory
WORKDIR /app

# Copy application code
COPY --chown=securechat:securechat . .

# Set permissions
RUN chmod +x client.py server.py

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import socket; socket.create_connection(('localhost', 12345), timeout=5)" || exit 1

# Expose default port
EXPOSE 12345

# Default command
CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "12345"]
