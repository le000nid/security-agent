FROM golang:1.24-bookworm AS nuclei-build
ARG NUCLEI_VERSION=v3.4.10
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

FROM python:3.12-slim
WORKDIR /agent
COPY requirements.txt .
# Semgrep's tracing dependency still imports pkg_resources.
RUN pip install --no-cache-dir -r requirements.txt semgrep==1.120.0 setuptools==80.9.0
COPY --from=nuclei-build /go/bin/nuclei /usr/local/bin/nuclei
COPY app ./app
COPY config ./config
COPY benchmark ./benchmark
COPY targets ./targets
RUN useradd --create-home agent && mkdir logs reports && chown -R agent:agent /agent
USER agent
ENTRYPOINT ["python", "-m", "app.main"]
