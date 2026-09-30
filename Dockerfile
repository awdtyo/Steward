# Multi-arch python:slim image; builds and runs on linux/arm64 (Pi 5).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only runtime deps first for better layer caching.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Run as a non-root user.
RUN useradd --create-home --uid 10001 steward \
    && chown -R steward:steward /app
USER steward

EXPOSE 8000

# Placeholder until the FastAPI app lands; keeps the container bootable.
CMD ["python", "-c", "import steward; print('steward', steward.__version__)"]
