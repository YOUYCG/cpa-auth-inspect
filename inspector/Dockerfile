FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUTH_DIR=/auths \
    PORT=18318 \
    HOST=0.0.0.0 \
    XAI_REAUTH_AUTO=1 \
    XAI_REAUTH_HEADLESS=0 \
    XAI_REAUTH_CONCURRENCY=1 \
    XAI_REAUTH_TIMEOUT=240

# Chromium + fonts for headed/headless device-consent automation.
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium \
      chromium-driver \
      fonts-liberation \
      fonts-noto-cjk \
      xvfb \
      xauth \
      ca-certificates \
      curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY xai_auto ./xai_auto
COPY codex_auto ./codex_auto
COPY turnstilePatch ./turnstilePatch

EXPOSE 18318
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "18318"]
