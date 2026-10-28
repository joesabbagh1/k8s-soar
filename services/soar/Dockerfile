# One source tree, three images:
#   docker build --target actions -t k8s-soar-actions .   (Argo workflow steps)
#   docker build --target console -t k8s-soar-console .   (analyst case UI)
#   docker build --target agent   -t k8s-soar-agent .     (AI triage service)
#
# Dependencies are installed in their own layer, from pyproject.toml and a stub
# package, so a code change only rebuilds the small final layer.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --uid 10001 --create-home soar
WORKDIR /app
COPY pyproject.toml README.md ./
RUN mkdir -p src/k8s_soar && touch src/k8s_soar/__init__.py

FROM base AS actions
RUN pip install . && pip uninstall -y -q k8s-soar
COPY src ./src
RUN pip install --no-deps .
USER 10001
ENTRYPOINT ["soar-actions"]

FROM base AS console
RUN pip install ".[console]" && pip uninstall -y -q k8s-soar
COPY src ./src
RUN pip install --no-deps .
USER 10001
EXPOSE 8080
ENTRYPOINT ["soar-console"]

FROM base AS agent
RUN pip install ".[agent]" && pip uninstall -y -q k8s-soar
COPY src ./src
RUN pip install --no-deps .
USER 10001
EXPOSE 8080
ENTRYPOINT ["soar-agent"]
