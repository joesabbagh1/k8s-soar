# One source tree, three images:
#   docker build --target actions -t k8s-soar-actions .   (Argo workflow steps)
#   docker build --target console -t k8s-soar-console .   (analyst case UI)
#   docker build --target agent   -t k8s-soar-agent .     (AI triage service)
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --uid 10001 --create-home soar
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

FROM base AS actions
RUN pip install .
USER 10001
ENTRYPOINT ["soar-actions"]

FROM base AS console
RUN pip install ".[console]"
USER 10001
EXPOSE 8080
ENTRYPOINT ["soar-console"]

FROM base AS agent
RUN pip install ".[agent]"
USER 10001
EXPOSE 8080
ENTRYPOINT ["soar-agent"]
