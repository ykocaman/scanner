# Vulnerability Scanner

A CLI that inventories packages installed on the local host and checks them
against CVE feeds — Red Hat, the Debian Security Tracker, Ubuntu's USN
database, and Alpine's secdb — reporting matches as a colored console
table, and optionally by email or into Elasticsearch.

### Demo
[![asciicast](https://asciinema.org/a/411920.svg)](https://asciinema.org/a/411920)

## How it works

1. Detects the host's package manager (apt, rpm, or apk) and inventories
   installed packages with it.
2. Fetches every enabled CVE source and matches it against that inventory:
   - **Red Hat** — substring match against the feed's affected
     package/version strings. Red Hat lists exact NVR strings, not version
     ranges, so this is a coarse heuristic, not a real comparison.
   - **Debian** / **Ubuntu** — matched against the release (suite) apt
     reports, using real dpkg version comparison against each CVE's
     `fixed_version`.
   - **Alpine** — matched with apk version comparison. Only useful on an
     actual Alpine host; on apt/rpm hosts Alpine's package set doesn't
     overlap with theirs.
3. Prints a per-package breakdown plus a severity/package summary table.
4. Optionally emails the summary and/or indexes each finding into
   Elasticsearch.
5. Exits with a status code reflecting the outcome (see [Exit codes](#exit-codes)),
   so it can be driven from cron or any other scheduler.

Treat results as a starting point, not a guarantee — see the matching notes
above for each source's limits.

## Requirements

- A Linux host (or container) with one of `apt`, `rpm`, or `apk` on `PATH`.
- Go 1.25+ to build from source.

## Build

```bash
make build   # -> bin/scanner
```

## Usage

```bash
./bin/scanner
```

Copy [.env.example](.env.example) to `.env` and adjust it to configure
sources, caching, email, and Elasticsearch (the scanner loads `.env`
automatically on startup via [godotenv](https://github.com/joho/godotenv)).

## Configuration

All settings are read from the environment.

| Variable            | Default                      | Description                                                |
| ------------------- | ----------------------------- | ----------------------------------------------------------|
| `HTTP_TIMEOUT`       | `5m`                          | Per-request HTTP timeout (Go duration, e.g. `90s`).         |
| `USE_REDHAT`         | `true`                        | Enable the Red Hat CVE feed.                                |
| `REDHAT_CVE_URL`     | Red Hat's CVE feed            | Feed URL to fetch and scan against.                         |
| `REDHAT_PER_PAGE`    | `1000`                        | Results per page when paginating the feed.                  |
| `USE_DEBIAN`         | `false`                       | Enable the Debian Security Tracker (~70MB feed).             |
| `DEBIAN_TRACKER_URL` | Debian's tracker feed         | Feed URL.                                                    |
| `USE_UBUNTU`         | `false`                       | Enable Ubuntu's USN database (hundreds of MB).               |
| `UBUNTU_USN_URL`     | Ubuntu's USN database         | Feed URL.                                                    |
| `USE_ALPINE`         | `false`                       | Enable Alpine secdb feeds (see the note above).              |
| `ALPINE_SECDB_URL`   | v3.24 `main` + `community`    | Comma-separated secdb feed URLs. Alpine versions its secdb by release, not by a stable alias — update this when the host's Alpine version moves on. |
| `USE_CACHING`        | `false`                       | Skip findings already reported by a previous run.            |
| `CACHE_PATH`         | `/tmp/scanner-cache`          | File used to persist which findings have already been seen.  |
| `SEND_MAIL`          | `false`                       | Email the summary table when vulnerabilities are found.      |
| `MAIL_SERVER_HOST`   | —                             | SMTP host.                                                   |
| `MAIL_SERVER_PORT`   | —                             | SMTP port.                                                   |
| `MAIL_USERNAME`      | —                             | SMTP username, also used as the `From` address.              |
| `MAIL_PASSWORD`      | —                             | SMTP password.                                               |
| `MAIL_TO`            | —                             | Report recipient.                                            |
| `USE_ELASTIC`        | `false`                       | Index every finding into Elasticsearch.                      |
| `ELASTIC_HOST`       | `http://127.0.0.1:9200`       | Elasticsearch URL.                                            |
| `ELASTIC_INDEX`      | `scanner`                     | Elasticsearch index name.                                    |

Debian, Ubuntu, and Alpine are off by default because their feeds are large
single JSON documents fetched in full on every run. Only Red Hat's feed is
paginated server-side; Debian and Ubuntu's are streamed and filtered
client-side instead, to keep memory bounded.

A failure in one enabled source is logged and skipped rather than aborting
the run — the scan only fails if every enabled source fails.

## Exit codes

| Code | Meaning                                    |
| ---- | ------------------------------------------- |
| `0`  | Scan completed, no vulnerabilities found.   |
| `1`  | Scan completed, vulnerabilities found.      |
| `2`  | Scan failed to run (network, inventory, etc.). |

## Docker

The provided [Dockerfile](Dockerfile) builds the scanner onto an
`ubuntu:24.04` image. **Replace the final-stage base image** with whatever
host you actually want scanned — the scanner reports on the image it runs
in, not your real host, unless you run the binary there directly. If you
swap in a different base image, make sure it has CA certificates installed
(`ca-certificates` on Debian/Ubuntu) — several minimal images don't ship
them, and every feed fetch is HTTPS.

```bash
docker build -t scanner .
docker run --rm --env-file .env scanner
```

[docker-compose.yml](docker-compose.yml) additionally wires up a local
Elasticsearch + Kibana stack and schedules the scan via the container's
system crontab (see [deploy/crontab](deploy/crontab)):

```bash
docker compose up
```

## Development

```bash
make test
make vet
make lint
make fmt
```

`make fix` runs [modernize](https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/modernize),
`gofumpt`, and `golangci-lint --fix`. Lint rules live in [.golangci.yml](.golangci.yml).

`make release-build VERSION=x.y.z` cross-compiles linux/amd64 and
linux/arm64 binaries into `dist/` (Linux only — see Requirements).

## Project layout

```
cmd/scanner/main.go        wires the pieces below together, detects the inventory
internal/
  config/                  environment-driven configuration
  models/                  shared data types (Component, RedhatCVE, Finding)
  cache/                   generic "have we reported this before" cache
  sources/                 one package per CVE feed, each exposing Scan(...)
    redhat/                pagination, indexing, substring matching
    debian/                streamed, dpkg-version matched
    ubuntu/                streamed, dpkg-version matched
    alpine/                apk-version matched
  inventory/               one package per package manager, each exposing List(...)
    apt/
    rpm/                   covers both yum and dnf (same underlying database)
    apk/
  version/                 package version comparison, one per ecosystem
    dpkg/                  Debian/Ubuntu (Policy §5.6.12)
    apk/                   Alpine (common cases only, see doc comment)
    verutil/               digit/non-digit run comparison shared by dpkg and apk
  output/
    report/                console table, tally, and email rendering
    elastic/               Elasticsearch sink
deploy/crontab             cron schedule used by docker-compose.yml
docs/ascii.cast             raw asciinema recording behind the demo badge
```

## License

[GPL-3.0](LICENSE)
