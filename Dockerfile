FROM --platform=$BUILDPLATFORM golang:1.27-alpine3.24 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apk add --no-cache ca-certificates curl unzip

WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY bermuda.jpg ./

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto

RUN set -eux; \
    test -s ./bermuda.jpg; \
    case "${TARGETARCH:-amd64}" in \
      arm64) export GOARCH=arm64 GOARM64=v8.0 ;; \
      *)     export GOARCH=amd64 GOAMD64=v2 ;; \
    esac; \
    GOOS="${TARGETOS:-linux}" go build -trimpath -tags netgo,osusergo -ldflags="-s -w -buildid=" \
      -o /out/usr/local/bin/bermuda-portal .

RUN set -eux; \
    mkdir -p /out/usr/local/bin /out/usr/local/share/router-assets /tmp/rt; \
    case "${TARGETARCH:-amd64}" in \
      arm64) ARCH_SUFFIX="arm64-v8a" ;; \
      *)     ARCH_SUFFIX="64" ;; \
    esac; \
    ARCHIVE="Xray-linux-${ARCH_SUFFIX}.zip"; \
    DOWNLOADED=0; \
    for CANDIDATE in \
      "https://github.com/XTLS/Xray-core/releases/latest/download" \
      "https://github.com/XTLS/Xray-core/releases/download/v26.11.9" \
      "https://github.com/XTLS/Xray-core/releases/download/v26.10.31" \
      "https://github.com/XTLS/Xray-core/releases/download/v26.10.21" \
      "https://github.com/XTLS/Xray-core/releases/download/v26.9.30" \
      "https://github.com/XTLS/Xray-core/releases/download/v26.7.28"; \
    do \
      rm -f /tmp/rt/worker.zip /tmp/rt/worker.zip.dgst; \
      if curl -fsSL --retry 2 --connect-timeout 15 "${CANDIDATE}/${ARCHIVE}" -o /tmp/rt/worker.zip && \
         curl -fsSL --retry 2 --connect-timeout 10 "${CANDIDATE}/${ARCHIVE}.dgst" -o /tmp/rt/worker.zip.dgst; then \
        EXPECTED_SHA=$(awk -F'= *' 'toupper($1) ~ /SHA2-256|SHA256/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /tmp/rt/worker.zip.dgst); \
        if printf '%s\n' "${EXPECTED_SHA}" | grep -Eq '^[0-9A-Fa-f]{64}$' && \
           printf '%s  %s\n' "${EXPECTED_SHA}" "/tmp/rt/worker.zip" | sha256sum -c -; then \
          DOWNLOADED=1; \
          break; \
        fi; \
      fi; \
    done; \
    if [ "${DOWNLOADED}" -ne 1 ]; then \
      echo "ERROR: All verified upstream worker archive candidates failed SHA-256 verification" >&2; \
      exit 1; \
    fi; \
    unzip -q /tmp/rt/worker.zip -d /tmp/rt; \
    mv /tmp/rt/xray /out/usr/local/bin/router-worker; \
    head -c 32 /dev/urandom >> /out/usr/local/bin/router-worker; \
    chmod 0755 /out/usr/local/bin/router-worker; \
    mv /tmp/rt/geoip.dat /out/usr/local/share/router-assets/geoip.dat; \
    mv /tmp/rt/geosite.dat /out/usr/local/share/router-assets/geosite.dat; \
    chmod 0644 /out/usr/local/share/router-assets/*.dat; \
    rm -rf /tmp/rt

FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata && \
    update-ca-certificates && \
    mkdir -p /tmp/bm-runtime && \
    chmod 1777 /tmp/bm-runtime

WORKDIR /app

COPY --from=builder /out/usr/local/bin/bermuda-portal /usr/local/bin/bermuda-portal
COPY --from=builder /out/usr/local/bin/router-worker /usr/local/bin/router-worker
COPY --from=builder /out/usr/local/share/router-assets /usr/local/share/router-assets

ENV PORT=8080 \
    BERMUDA_LISTEN_PORT=8080 \
    BERMUDA_ASSET_DIR=/usr/local/share/router-assets

EXPOSE 8080 3000 80

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/bermuda-portal"]
