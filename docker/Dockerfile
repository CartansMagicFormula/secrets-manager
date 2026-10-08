# secrets-manager: static Go binary (standard library only) in an empty image.
# No OS, no shell, no package manager. Build context: repository root.

FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY web/ web/
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags "-s -w" -o /out/secrets-manager ./cmd/secrets-manager \
    && mkdir -p /out/data

FROM scratch
COPY --from=build /out/secrets-manager /secrets-manager
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8200
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 CMD ["/secrets-manager", "healthcheck"]
ENTRYPOINT ["/secrets-manager"]
