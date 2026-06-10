FROM golang:1.22 AS compile-tool
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /warmor-compile ./cmd/warmor-compile
RUN CGO_ENABLED=0 go build -o /warmor-daemon ./cmd/warmor-daemon

FROM rust:1.78-slim AS policy-builder
RUN rustup target add wasm32-wasi
COPY --from=compile-tool /warmor-compile /usr/local/bin/warmor-compile
COPY deploy/helm/warmor/policies/default.yaml /build/policy.yaml
RUN warmor-compile -o /build/policy.wasm /build/policy.yaml

FROM gcr.io/distroless/static:nonroot
COPY --from=compile-tool /warmor-daemon /warmor-daemon
COPY --from=policy-builder /build/policy.wasm /etc/warmor/policy.wasm
USER nonroot:nonroot
EXPOSE 9090
ENTRYPOINT ["/warmor-daemon"]
CMD ["-policy", "/etc/warmor/policy.wasm", "-metrics-port", "9090"]
