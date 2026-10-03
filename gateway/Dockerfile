FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS base
WORKDIR /app/gateway
ENV PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY gateway/pyproject.toml gateway/uv.lock ./
RUN uv sync --locked --no-dev
COPY gateway/ ./
COPY policy/ /app/policy/
COPY demo/ /app/demo/
ENV PATH="/app/gateway/.venv/bin:$PATH"
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS test
RUN uv sync --locked
COPY tests/ /app/tests/
CMD ["pytest", "-q"]

FROM base AS runtime
