FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /warmor-daemon ./cmd/warmor-daemon

FROM gcr.io/distroless/static:latest
COPY --from=builder /warmor-daemon /warmor-daemon
EXPOSE 9090
ENTRYPOINT ["/warmor-daemon"]
