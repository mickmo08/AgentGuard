# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY agentguard ./agentguard
# Behind a TLS-intercepting proxy? Pass its CA without baking it into the image:
#   docker build --secret id=pip_ca,src=/path/to/ca-bundle.crt .
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -f /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    pip wheel --no-cache-dir --wheel-dir /wheels ".[server,mcp]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    AGENTGUARD_DATABASE_URL=sqlite:////data/agentguard.db
RUN useradd --system --uid 10001 --home /data agentguard && mkdir -p /data && chown agentguard /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels
USER agentguard
WORKDIR /data
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/readyz').status==200 else 1)"
CMD ["agentguard", "serve", "--host", "0.0.0.0", "--port", "8080", "--forwarded-allow-ips", "*"]
