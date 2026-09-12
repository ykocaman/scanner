FROM golang:1.25-bookworm AS build
WORKDIR /build/
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o scanner ./cmd/scanner

# Replace this with whatever Debian/Ubuntu-based image represents the host
# you actually want scanned; the scanner shells out to `apt` to build its
# package inventory.
FROM ubuntu:24.04 AS final
# `cron` runs as root by design (see docker-compose.yml, which schedules the
# scan via the system crontab); it is not preinstalled in the base image.
# `ca-certificates` isn't preinstalled either — without it every HTTPS CVE
# feed fetch fails with "x509: certificate signed by unknown authority".
RUN apt-get update && apt-get install -y --no-install-recommends cron ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/scanner /bin/scanner
CMD ["/bin/scanner"]
