# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.24.13-bookworm AS nuclei-build
ARG TARGETOS
ARG TARGETARCH
ARG NUCLEI_VERSION=v3.4.10
RUN test "$TARGETOS" = linux && case "$TARGETARCH" in amd64|arm64) ;; *) exit 1 ;; esac
# Go verifies downloaded module checksums through sum.golang.org.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} && \
    mkdir -p /out && find /go/bin -type f -name nuclei -exec cp {} /out/nuclei \;

FROM python:3.11.14-slim-bookworm
WORKDIR /agent
ARG SEMGREP_VERSION=1.120.0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp/agent-home
COPY requirements.txt ./
# Semgrep's tracing dependency still imports pkg_resources.
RUN pip install --no-cache-dir -r requirements.txt semgrep==${SEMGREP_VERSION} setuptools==80.9.0
COPY --from=nuclei-build /out/nuclei /usr/local/bin/nuclei
COPY app ./app
COPY config ./config
COPY benchmark ./benchmark
COPY targets ./targets
COPY pyproject.toml ./
RUN pip install --no-cache-dir --no-deps --no-build-isolation . && \
    useradd --uid 1000 --create-home agent && \
    mkdir -p logs reports runs /tmp/agent-home && \
    chown -R agent:agent logs reports runs /tmp/agent-home && \
    semgrep --version && nuclei -version
USER 1000:1000
ENTRYPOINT ["security-agent"]
CMD ["--help"]
