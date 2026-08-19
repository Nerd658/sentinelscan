package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	opensearch "github.com/opensearch-project/opensearch-go/v2"
	opensearchapi "github.com/opensearch-project/opensearch-go/v2/opensearchapi"
	"sentinelscan/pkg/config"
	"sentinelscan/pkg/logger"
)

type SearchResult struct {
	ID         string          `json:"id"`
	Index      string          `json:"index"`
	Score      float64         `json:"score"`
	SourceData json.RawMessage `json:"source"`
}

type Client struct {
	client      *opensearch.Client
	indexPrefix string
}

func NewOpenSearchClient(cfg config.OpenSearchConfig) (*Client, error) {
	client, err := opensearch.NewClient(opensearch.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Transport: &http.Transport{
			ResponseHeaderTimeout: 5 * time.Second,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize opensearch client: %w", err)
	}

	return &Client{
		client:      client,
		indexPrefix: cfg.IndexPrefix,
	}, nil
}

func (c *Client) Ping(ctx context.Context) error {
	req := opensearchapi.InfoRequest{}
	res, err := req.Do(ctx, c.client)
	if err != nil {
		return fmt.Errorf("failed opensearch ping: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("opensearch ping returned error status: %s", res.Status())
	}
	return nil
}

func (c *Client) EnsureIndex(ctx context.Context, name string) error {
	indexName := fmt.Sprintf("%s-%s", c.indexPrefix, name)
	req := opensearchapi.IndicesExistsRequest{
		Index: []string{indexName},
	}

	res, err := req.Do(ctx, c.client)
	if err != nil {
		return fmt.Errorf("failed to check index existence %s: %w", indexName, err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		return nil // Index exists
	}

	// Create index with mapping
	mapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"ip": { "type": "keyword" },
				"port": { "type": "integer" },
				"service": { "type": "keyword" },
				"hostname": { "type": "keyword" },
				"ssl": {
					"properties": {
						"cert": {
							"properties": {
								"subject": {
									"properties": {
										"cn": { "type": "keyword" }
									}
								},
								"issuer": { "type": "keyword" }
							}
						}
					}
				},
				"http": {
					"properties": {
						"server": { "type": "keyword" },
						"status_code": { "type": "integer" },
						"title": { "type": "text" }
					}
				},
				"technology": { "type": "keyword" },
				"first_seen": { "type": "date" },
				"last_seen": { "type": "date" }
			}
		}
	}`

	createReq := opensearchapi.IndicesCreateRequest{
		Index: indexName,
		Body:  strings.NewReader(mapping),
	}

	createRes, err := createReq.Do(ctx, c.client)
	if err != nil {
		return fmt.Errorf("failed to create index %s: %w", indexName, err)
	}
	defer createRes.Body.Close()

	if createRes.IsError() {
		return fmt.Errorf("failed index creation %s: %s", indexName, createRes.Status())
	}

	logger.Info("Created OpenSearch index", "index", indexName)
	return nil
}

func (c *Client) IndexDocument(ctx context.Context, indexSuffix, docID string, doc interface{}) error {
	indexName := fmt.Sprintf("%s-%s", c.indexPrefix, indexSuffix)

	bodyBytes, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal opensearch document: %w", err)
	}

	req := opensearchapi.IndexRequest{
		Index:      indexName,
		DocumentID: docID,
		Body:       bytes.NewReader(bodyBytes),
		Refresh:    "true",
	}

	res, err := req.Do(ctx, c.client)
	if err != nil {
		return fmt.Errorf("failed to index document %s: %w", docID, err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("indexing document error status: %s", res.Status())
	}

	return nil
}

func (c *Client) Search(ctx context.Context, indexSuffix, query string) ([]SearchResult, error) {
	indexName := fmt.Sprintf("%s-%s", c.indexPrefix, indexSuffix)

	searchQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"query_string": map[string]interface{}{
				"query": query,
			},
		},
	}

	queryBytes, err := json.Marshal(searchQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal search query: %w", err)
	}

	req := opensearchapi.SearchRequest{
		Index: []string{indexName},
		Body:  bytes.NewReader(queryBytes),
	}

	res, err := req.Do(ctx, c.client)
	if err != nil {
		return nil, fmt.Errorf("search query execution failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search response error: %s", res.Status())
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read search response body: %w", err)
	}

	var response struct {
		Hits struct {
			Hits []struct {
				ID     string          `json:"_id"`
				Index  string          `json:"_index"`
				Score  float64         `json:"_score"`
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse search result json: %w", err)
	}

	results := make([]SearchResult, 0, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		results = append(results, SearchResult{
			ID:         hit.ID,
			Index:      hit.Index,
			Score:      hit.Score,
			SourceData: hit.Source,
		})
	}

	return results, nil
}
