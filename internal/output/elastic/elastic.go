// Package elastic indexes scan findings into Elasticsearch.
package elastic

import (
	"context"
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"

	"github.com/ykocaman/scanner/internal/config"
	"github.com/ykocaman/scanner/internal/models"
)

// Client indexes findings into a single Elasticsearch index.
type Client struct {
	es    *elastic.Client
	index string
}

// NewClient connects to the Elasticsearch cluster described by cfg.
func NewClient(cfg config.Config) (*Client, error) {
	es, err := elastic.NewClient(elastic.SetURL(cfg.ElasticHost))
	if err != nil {
		return nil, fmt.Errorf("connecting to elasticsearch: %w", err)
	}
	return &Client{es: es, index: cfg.ElasticIndex}, nil
}

type document struct {
	Source          string
	Code            string
	Severity        string
	AffectedPackage string
	AffectedVersion string
	URL             string
	Description     string
	Score           string
	PublicDate      string
	DetectionDate   string
}

// Index writes a single finding into Elasticsearch.
func (c *Client) Index(ctx context.Context, f models.Finding) error {
	doc := document{
		Source:          f.Source,
		Code:            f.Code,
		Severity:        f.Severity,
		PublicDate:      f.PublicDate,
		DetectionDate:   time.Now().Format(time.RFC3339),
		URL:             f.URL,
		Description:     f.Description,
		Score:           f.Score,
		AffectedPackage: f.Component.Name,
		AffectedVersion: f.Component.Version,
	}

	if _, err := c.es.Index().Index(c.index).BodyJson(doc).Do(ctx); err != nil {
		return fmt.Errorf("indexing document: %w", err)
	}
	return nil
}
