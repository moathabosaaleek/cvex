// Package feed pulls items from the outside world. Collectors here must not
// touch the database; the service decides what gets written.
package feed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/moathabosaaleek/cvex/internal/core/model"
)

const defaultUA = "cvex/0.1 (+https://github.com/moathabosaaleek/cvex)"

// Some WAFs reject anything that doesn't look like a browser. At least one
// source does the exact opposite: BleepingComputer serves a plain client fine
// and 403s Chrome. There is no right global answer, so it's per-source.
const browserUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// Conditional is what a source told us last time, so the next fetch can ask
// for nothing if nothing changed. KEV and EPSS are both multi-megabyte files
// that rarely move, so this is worth doing properly.
type Conditional struct {
	ETag         string
	LastModified string
}

// Result is deliberately one type for all three source shapes. KEV produces
// CVE items and KEV rows, EPSS produces only scores, RSS produces only items.
// Three interfaces for that would be worse.
type Result struct {
	Items     []model.Item
	KEV       []model.KEVEntry
	EPSS      []model.EPSSScore
	Next      Conditional
	Unchanged bool
}

type Collector interface {
	Name() string
	Collect(ctx context.Context, f *Fetcher, prev Conditional) (Result, error)
}

type Fetcher struct {
	client *http.Client
}

func NewFetcher() *Fetcher {
	// EPSS is ~20MB gzipped and CISA is occasionally slow, so this is generous
	// on purpose.
	return &Fetcher{client: &http.Client{Timeout: 90 * time.Second}}
}

type response struct {
	body         []byte
	etag         string
	lastModified string
	notModified  bool
}

func (f *Fetcher) get(ctx context.Context, url string, prev Conditional) (*response, error) {
	return f.getAs(ctx, url, defaultUA, prev)
}

func (f *Fetcher) getAs(ctx context.Context, url, ua string, prev Conditional) (*response, error) {
	if ua == "" {
		ua = defaultUA
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return &response{notModified: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &response{
		body:         body,
		etag:         resp.Header.Get("ETag"),
		lastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

var cveRE = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// ExtractCVEs scrapes CVE ids out of free text. This is the whole mechanism by
// which a news headline ends up linked to the CVE record it's about.
func ExtractCVEs(texts ...string) []model.Entity {
	seen := make(map[string]bool)
	var out []model.Entity
	for _, t := range texts {
		for _, m := range cveRE.FindAllString(t, -1) {
			id := strings.ToUpper(m)
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, model.Entity{Kind: model.EntityCVE, Value: id})
		}
	}
	return out
}

func itemID(source, externalID string) string {
	return source + ":" + externalID
}
