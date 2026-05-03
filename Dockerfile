FROM node:22-alpine AS ui-build
WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM python:3.13-slim AS gateway
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8000

WORKDIR /app
RUN useradd --create-home --shell /usr/sbin/nologin murdoc

COPY pyproject.toml README.md ./
COPY murdoc ./murdoc
COPY --from=ui-build /app/ui/dist ./ui/dist

ARG PIP_EXTRAS=""
RUN if [ -n "$PIP_EXTRAS" ]; then \
      pip install ".[${PIP_EXTRAS}]"; \
    else \
      pip install "."; \
    fi

RUN mkdir -p /app/logs /app/state && chown -R murdoc:murdoc /app
USER murdoc

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"

CMD ["python", "-m", "uvicorn", "murdoc.gateway.app:app", "--host", "0.0.0.0", "--port", "8000"]
