# Dockerfile (Production-focused)

# ---- Builder Stage (to install dependencies) ----
FROM python:3.11-slim as builder

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

WORKDIR /opt/venv
RUN python -m venv .
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- Runner Stage (final image) ----
FROM python:3.11-slim as runner

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV HOST="0.0.0.0"
ENV PORT="8000"
# Set GUNICORN_CMD_ARGS for more workers in production, e.g.
ENV GUNICORN_CMD_ARGS="--workers 4 --worker-class uvicorn.workers.UvicornWorker"


WORKDIR /app

# Create a non-root user and group
RUN groupadd -r ospgroup --gid 1000 && \
    useradd --no-log-init -r -g ospgroup --uid 1000 ospuser

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --chown=ospuser:ospgroup ./app /app/app

# Set PATH to use the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Switch to non-root user
USER ospuser

# Expose the port the app runs on
EXPOSE 8000

# Run the application with Gunicorn for production
# Uvicorn recommends Gunicorn for managing Uvicorn workers in production.
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", "--bind", "0.0.0.0:8000", "--workers", "4"]
# Alternative: uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 (if Uvicorn supports --workers directly in your version)
# The number of workers depends on your server's CPU cores: (2 * NUM_CORES) + 1 is a common starting point.