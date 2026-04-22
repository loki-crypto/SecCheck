FROM python:3.11-slim

# Labels
LABEL maintainer="DevSecOps Team"
LABEL version="1.0.0"
LABEL description="Security Checklist - DevSecOps Platform"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV HOST=0.0.0.0
ENV PORT=9090

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/data /app/uploads /app/app/static /app/secrets /app/logs && \
    chmod -R 755 /app

# Create non-root user for security
RUN adduser --disabled-password --gecos '' --uid 1000 appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT:-9090}/health || exit 1

# Run application with uvicorn for production
CMD ["sh", "-c", "python -m uvicorn main:app --host ${HOST:-0.0.0.0} --port ${PORT:-9090}"]
