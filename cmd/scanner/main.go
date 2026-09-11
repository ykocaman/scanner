// Command scanner cross-references packages installed on this host
// against several distro CVE feeds and reports any matches.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"

	"github.com/fatih/color"
	"github.com/joho/godotenv"

	"github.com/ykocaman/scanner/internal/cache"
	"github.com/ykocaman/scanner/internal/config"
	apkinventory "github.com/ykocaman/scanner/internal/inventory/apk"
	"github.com/ykocaman/scanner/internal/inventory/apt"
	"github.com/ykocaman/scanner/internal/inventory/rpm"
	"github.com/ykocaman/scanner/internal/models"
	"github.com/ykocaman/scanner/internal/output/elastic"
	"github.com/ykocaman/scanner/internal/output/report"
	"github.com/ykocaman/scanner/internal/sources/alpine"
	"github.com/ykocaman/scanner/internal/sources/debian"
	"github.com/ykocaman/scanner/internal/sources/redhat"
	"github.com/ykocaman/scanner/internal/sources/ubuntu"
)

// Exit codes so cron/monitoring can distinguish a clean scan from one that
// found vulnerabilities from one that failed to run at all.
const (
	exitClean        = 0
	exitVulnerable   = 1
	exitRuntimeError = 2
)

// scanFunc is the shape every CVE source exposes: fetch its feed and
// return whatever Findings it produces against components.
type scanFunc func(ctx context.Context, client *http.Client, cfg config.Config, components []models.Component) ([]models.Finding, error)

func main() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: failed to load .env: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, config.Load())
	stop()

	os.Exit(code)
}

func run(ctx context.Context, cfg config.Config) int {
	inv, ok := detectInventory()
	if !ok {
		log.Println("no supported package manager found (looked for apt, rpm, apk)")
		return exitRuntimeError
	}

	components, err := inv.list(ctx)
	if err != nil {
		log.Println(err)
		return exitRuntimeError
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	all, ok := scanSources(ctx, httpClient, cfg, components)
	if !ok {
		return exitRuntimeError
	}

	findings := all
	var c *cache.Cache
	if cfg.UseCaching {
		if c, err = cache.Open(cfg.CachePath); err != nil {
			log.Println(err)
			return exitRuntimeError
		}
		findings = newFindings(all, c)
	}

	esClient, err := newElasticClient(cfg)
	if err != nil {
		log.Println(err)
		return exitRuntimeError
	}

	printFindings(findings)
	indexFindings(ctx, esClient, findings)

	if c != nil {
		markSeen(c, all)
	}

	return reportFindings(cfg, findings)
}

type namedInventory struct {
	name  string
	probe string // binary whose presence on PATH identifies this package manager
	list  func(context.Context) ([]models.Component, error)
}

// inventories lists every supported package manager, most specific
// first (rpm and apk are never both present alongside apt in practice,
// so order mostly matters for which error message wins if none match).
var inventories = []namedInventory{
	{"apt", "apt", apt.List},
	{"rpm", "rpm", rpm.List},
	{"apk", "apk", apkinventory.List},
}

// detectInventory returns the first inventory whose package manager
// binary is present on PATH.
func detectInventory() (namedInventory, bool) {
	for _, inv := range inventories {
		if _, err := exec.LookPath(inv.probe); err == nil {
			return inv, true
		}
	}
	return namedInventory{}, false
}

type namedSource struct {
	name string
	scan scanFunc
}

// enabledSources returns the scan function for every source enabled in
// cfg, in a fixed order so output and logs stay stable across runs.
func enabledSources(cfg config.Config) []namedSource {
	var sources []namedSource
	if cfg.Redhat.Enabled {
		sources = append(sources, namedSource{"redhat", redhat.Scan})
	}
	if cfg.Debian.Enabled {
		sources = append(sources, namedSource{"debian", debian.Scan})
	}
	if cfg.Ubuntu.Enabled {
		sources = append(sources, namedSource{"ubuntu", ubuntu.Scan})
	}
	if cfg.Alpine.Enabled {
		sources = append(sources, namedSource{"alpine", alpine.Scan})
	}
	return sources
}

// scanSources runs every enabled source and collects their findings. A
// single source failing (e.g. a slow/unreachable feed) doesn't abort the
// others; the run is only considered a failure if every enabled source
// fails, or ok is false.
func scanSources(ctx context.Context, client *http.Client, cfg config.Config, components []models.Component) (findings []models.Finding, ok bool) {
	sources := enabledSources(cfg)
	if len(sources) == 0 {
		log.Println("no CVE sources enabled; nothing to scan")
		return nil, true
	}

	succeeded := 0
	for _, s := range sources {
		found, err := s.scan(ctx, client, cfg, components)
		if err != nil {
			log.Printf("%s: %v", s.name, err)
			continue
		}
		succeeded++
		findings = append(findings, found...)
	}

	return findings, succeeded > 0
}

// findingKey identifies a finding for caching purposes: the same CVE
// code from the same source affecting a different package should still
// be reported, so the package name is part of the key.
func findingKey(f models.Finding) string {
	return f.Source + ":" + f.Code + ":" + f.Component.Name
}

// newFindings returns the subset of all not already recorded in c.
func newFindings(all []models.Finding, c *cache.Cache) []models.Finding {
	fresh := all[:0]
	for _, f := range all {
		if !c.Seen(findingKey(f)) {
			fresh = append(fresh, f)
		}
	}
	return fresh
}

func markSeen(c *cache.Cache, all []models.Finding) {
	for _, f := range all {
		if err := c.Mark(findingKey(f)); err != nil {
			log.Println(err)
		}
	}
}

func newElasticClient(cfg config.Config) (*elastic.Client, error) {
	if !cfg.UseElastic {
		return nil, nil //nolint:nilnil // no client wanted when Elastic indexing is disabled
	}
	return elastic.NewClient(cfg)
}

// printFindings writes one block per affected component to stdout,
// grouping together findings from every source that flagged it.
func printFindings(findings []models.Finding) {
	var order []string
	byComponent := make(map[string][]models.Finding)
	for _, f := range findings {
		if _, seen := byComponent[f.Component.Name]; !seen {
			order = append(order, f.Component.Name)
		}
		byComponent[f.Component.Name] = append(byComponent[f.Component.Name], f)
	}

	for _, name := range order {
		group := byComponent[name]
		c := group[0].Component
		fmt.Println(color.BlueString("%s, %s (%s)", c.Name, c.Version, c.RawVersion))

		for _, f := range group {
			report.PrintFinding(f)
		}
		fmt.Println(color.RedString("Count: %d", len(group)))
	}
}

func indexFindings(ctx context.Context, esClient *elastic.Client, findings []models.Finding) {
	if esClient == nil {
		return
	}
	for _, f := range findings {
		if err := esClient.Index(ctx, f); err != nil {
			log.Println(err)
		}
	}
}

// reportFindings renders the summary table and, if configured, emails it.
// It returns the process exit code for the scan as a whole.
func reportFindings(cfg config.Config, findings []models.Finding) int {
	t, total := report.BuildTable(report.Tally(findings))
	if total == 0 {
		fmt.Println(color.GreenString("No new vulnerabilities detected!"))
		return exitClean
	}

	fmt.Println()
	fmt.Println(t.Render())

	if cfg.SendMail {
		if err := report.SendMail(cfg, t.RenderHTML(), total); err != nil {
			log.Printf("sending report email: %v", err)
		}
	}

	return exitVulnerable
}
