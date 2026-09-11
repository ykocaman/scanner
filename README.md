# Vulnerability Scanner

A small CLI that checks the packages installed on a Debian/Ubuntu host
against up to four CVE feeds — Red Hat, the Debian Security Tracker,
Ubuntu's USN database, and Alpine's secdb — and reports any matches as a
colored console table, and optionally by email or into Elasticsearch.

### Demo
[![asciicast](https://asciinema.org/a/411920.svg)](https://asciinema.org/a/411920)

## How it works

1. Runs `apt list --installed` to inventory packages on the local host.
2. Fetches every enabled CVE source and matches it against that inventory:
   - **Red Hat** — substring match against the feed's affected
     package/version strings (see the caveat below).
   - **Debian** / **Ubuntu** — matched against the release (suite) your apt
     repo reports, using a real dpkg version comparison
     (`internal/version/dpkg`) against each CVE's `fixed_version`.
   - **Alpine** — matched with a best-effort apk version comparison
     (`internal/version/apk`); see [internal/sources/alpine](internal/sources/alpine/alpine.go)
     for why this rarely applies to an apt-based host.
3. Prints a per-package breakdown plus a severity/package summary table.
4. Optionally emails the summary and/or indexes each finding into
   Elasticsearch.
5. Exits with a status code reflecting the outcome (see [Exit codes](#exit-codes)),
   so it can be driven from cron or any other scheduler/monitor.

> **Note on matching:** Red Hat's feed lists exact affected package/version
> strings rather than version ranges, so a component is flagged when its
> version string appears as a substring of one of those entries. This is a
> low-effort heuristic, not a real version-range comparison. Debian/Ubuntu
> matching is more rigorous (real version comparison against a real fixed
> version) but only as good as apt's release/repo metadata. Treat every
> result as a starting point for investigation, not a guarantee.

## Requirements

- A Debian/Ubuntu-based host (or container) with `apt` on `PATH` — this is
  what the scanner inventories. (Nothing currently inventories Alpine/apk
  hosts; see the note on the Alpine source above.)
- Go 1.23+ to build from source.

## Build

```bash
make build
```

This builds `bin/scanner`.

## Usage

```bash
./bin/scanner
```

Copy [.env.example](.env.example) to `.env` and adjust it to configure
caching, email, and Elasticsearch (the scanner loads `.env` automatically on
startup via [godotenv](https://github.com/joho/godotenv)).

## Configuration

All settings are read from the environment.

| Variable             | Default                        | Description                                                |
| -------------------- | ------------------------------- | ----------------------------------------------------------|
| `HTTP_TIMEOUT`        | `5m`                            | Per-request HTTP timeout (Go duration, e.g. `90s`).         |
| `USE_REDHAT`          | `true`                          | Enable the Red Hat CVE feed.                                |
| `REDHAT_CVE_URL`      | Red Hat's CVE feed              | Feed URL to fetch and scan against.                         |
| `REDHAT_PER_PAGE`     | `1000`                          | Results per page when paginating the feed.                  |
| `USE_DEBIAN`          | `false`                         | Enable the Debian Security Tracker (~70MB feed).             |
| `DEBIAN_TRACKER_URL`  | Debian's tracker feed           | Feed URL.                                                    |
| `USE_UBUNTU`          | `false`                         | Enable Ubuntu's USN database (hundreds of MB — see below).   |
| `UBUNTU_USN_URL`      | Ubuntu's USN database           | Feed URL.                                                    |
| `USE_ALPINE`          | `false`                         | Enable an Alpine secdb feed (rarely matches an apt host — see above). |
| `ALPINE_SECDB_URL`    | Alpine v3.20 community secdb    | Feed URL — point this at whichever Alpine release/repo you care about. |
| `USE_CACHING`         | `false`                         | Skip findings already reported by a previous run.            |
| `CACHE_PATH`          | `/tmp/scanner-cache`            | File used to persist which findings have already been seen.  |
| `SEND_MAIL`           | `false`                         | Email the summary table when vulnerabilities are found.      |
| `MAIL_SERVER_HOST`    | —                               | SMTP host.                                                   |
| `MAIL_SERVER_PORT`    | —                               | SMTP port.                                                   |
| `MAIL_USERNAME`       | —                               | SMTP username, also used as the `From` address.              |
| `MAIL_PASSWORD`       | —                               | SMTP password.                                               |
| `MAIL_TO`             | —                               | Report recipient.                                            |
| `USE_ELASTIC`         | `false`                         | Index every finding into Elasticsearch.                      |
| `ELASTIC_HOST`        | `http://127.0.0.1:9200`         | Elasticsearch URL.                                            |
| `ELASTIC_INDEX`       | `scanner`                       | Elasticsearch index name.                                    |

Debian, Ubuntu, and Alpine are off by default: their feeds are large single
JSON documents (Ubuntu's is several hundred MB) fetched in full on every
enabled run, so opt in deliberately. Red Hat's feed is the only one that's
genuinely paginated server-side; the others don't support it, so the scanner
streams and filters them client-side to keep memory bounded instead
(`internal/sources/debian` and `internal/sources/ubuntu`).

A failure in one enabled source (e.g. a slow/unreachable feed) is logged and
skipped rather than aborting the run — the scan only fails outright if every
enabled source fails.

## Exit codes

| Code | Meaning                                    |
| ---- | ------------------------------------------- |
| `0`  | Scan completed, no vulnerabilities found.   |
| `1`  | Scan completed, vulnerabilities found.      |
| `2`  | Scan failed to run (network, apt, etc.).    |

## Docker

The provided [Dockerfile](Dockerfile) builds the scanner and layers it onto
an `ubuntu:24.04` image so the packages it inventories are reproducible.
**Replace the final-stage base image** with whatever host you actually want
scanned — the scanner always reports on the image it runs in, not your real
host, unless you run the binary directly there.

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

`make fix` additionally runs [modernize](https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/modernize)
and applies `golangci-lint --fix`. Lint rules live in [.golangci.yml](.golangci.yml).

## Project layout

```
cmd/scanner/main.go        orchestration: wires the pieces below together
internal/
  config/                  environment-driven configuration
  models/                  shared data types (Component, RedhatCVE, Finding)
  cache/                   generic "have we reported this before" cache
  sources/                 one package per CVE feed, each exposing Scan(...)
    redhat/                Red Hat: pagination, indexing, substring matching
    debian/                Debian Security Tracker: streamed + dpkg-version matched
    ubuntu/                Ubuntu USN database: streamed + dpkg-version matched
    alpine/                Alpine secdb: apk-version matched (see caveat above)
  inventory/
    apt/                   apt-based installed-package inventory
  version/                 package version comparison, one per ecosystem
    dpkg/                  Debian/Ubuntu version comparison (Policy §5.6.12)
    apk/                   Alpine version comparison (best-effort, see doc comment)
    verutil/               digit/non-digit run comparison shared by dpkg and apk
  output/
    report/                console table, tally, and email rendering
    elastic/                Elasticsearch sink
deploy/crontab             cron schedule used by docker-compose.yml
docs/ascii.cast             raw asciinema recording behind the demo badge
```

## License

[GPL-3.0](LICENSE)
