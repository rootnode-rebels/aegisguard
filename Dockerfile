# ==============================================================================
# AWSSecurity AI - Standalone Zero-AWS Container
# Runs the full cybersecurity suite locally or on any server without AWS accounts.
# ==============================================================================
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY backend/ ./backend/
COPY database/ ./database/
COPY frontend/ ./frontend/
COPY data/ ./data/
COPY run_standalone.py .

# Environment Defaults: Standalone Zero-AWS Mode
ENV DEPLOYMENT_MODE="STANDALONE_LOCAL"
ENV PORT=8000
ENV HOST="0.0.0.0"

EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/system/status || exit 1

# Launch standalone server
CMD ["python", "run_standalone.py"]
