# ----------- BUILD STAGE -----------
FROM python:3.13.3-slim-bookworm AS build

# Set environment variables for Python and apt
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/root/.local/bin:$PATH"

# Install system dependencies and uv package manager
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    curl build-essential ca-certificates && \
    curl -LsSf https://astral.sh/uv/install.sh | sh && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory for the build stage
WORKDIR /app

# Copy dependency files to leverage Docker cache
COPY ./pyproject.toml ./uv.lock ./

# Install Python dependencies using uv
RUN uv sync

# Copy the application source code
COPY ./auth_service .

# Collect static files for production
RUN uv run manage.py collectstatic --noinput 

# ----------- RUNTIME STAGE -----------
FROM python:3.13.3-slim-bookworm AS runtime

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# Create a non-root user and group for running the app
RUN groupadd -r appgroup && \
    useradd -rg appgroup -m -d /home/appuser -s /usr/sbin/nologin appuser

# Set the working directory for the runtime stage
WORKDIR /app

# Copy built application and dependencies from build stage, set ownership
COPY --chown=appuser:appgroup --from=build /app .

# Switch to the non-root user
USER appuser

# Expose the application port
EXPOSE 8000

# Start the application using Gunicorn with Uvicorn worker
CMD ["/app/.venv/bin/gunicorn", "-k", "uvicorn.workers.UvicornWorker", "auth_service.asgi:application", "--bind", "0.0.0.0:8000", "--workers", "4"]
