// Package model holds the types the engine and every UI share.
// Nothing in here may import a presentation package.
package model

import "time"

type Kind string

const (
	KindCVE    Kind = "cve"
	KindNews   Kind = "news"
	KindPoC    Kind = "poc"
	KindBreach Kind = "breach"
	KindPost   Kind = "post"
)

type EntityKind string

const (
	EntityCVE     EntityKind = "cve"
	EntityVendor  EntityKind = "vendor"
	EntityProduct EntityKind = "product"
	EntityActor   EntityKind = "actor"
	EntityCWE     EntityKind = "cwe"
)

// Entity is a thing an item is about. The point of normalising these is that a
// CVE named in a news headline and the CVE record itself become the same node,
// so "everything about CVE-2026-1234" is a join and not a text search.
type Entity struct {
	Kind  EntityKind `json:"kind"`
	Value string     `json:"value"`
}

// Item is one row in the feed, whatever produced it.
type Item struct {
	ID         string `json:"id"` // source:external_id
	Source     string `json:"source"`
	ExternalID string `json:"external_id"`
	Kind       Kind   `json:"kind"`
	Title      string `json:"title"`
	Summary    string `json:"summary"`
	URL        string `json:"url"`

	// Pointer because feeds leave this out constantly, and time.Time's zero
	// value is year 1, which sorts to the bottom and stays there unnoticed.
	Published *time.Time `json:"published"`

	Fetched  time.Time `json:"fetched"`
	Starred  bool      `json:"starred"`
	Score    Score     `json:"score"`
	Entities []Entity  `json:"entities,omitempty"`

	// Original payload. Keep it: the parsers will change, and re-parsing what's
	// already on disk beats re-fetching months of feeds that have moved on.
	Raw []byte `json:"-"`

	// Other items judged to be the same story. Collapsed at query time, not on
	// write, so the dedup rules can change without a reimport.
	Duplicates []Item `json:"duplicates,omitempty"`
}

func (i Item) CVEs() []string {
	var out []string
	for _, e := range i.Entities {
		if e.Kind == EntityCVE {
			out = append(out, e.Value)
		}
	}
	return out
}

// Score doubles as the explanation. Reasons exists so ranking can be debugged
// by reading the feed instead of the scorer.
type Score struct {
	Total      float64  `json:"total"`
	InKEV      bool     `json:"in_kev"`
	Ransomware bool     `json:"ransomware"`
	EPSS       *float64 `json:"epss"`
	Reasons    []string `json:"reasons,omitempty"`
}

type FeedQuery struct {
	Kinds       []Kind     `json:"kinds,omitempty"`
	Search      string     `json:"search,omitempty"`
	StarredOnly bool       `json:"starred_only,omitempty"`
	Since       *time.Time `json:"since,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Offset      int        `json:"offset,omitempty"`
}

type EPSSScore struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

type KEVEntry struct {
	CVE        string     `json:"cve"`
	DateAdded  *time.Time `json:"date_added"`
	Ransomware bool       `json:"ransomware"`
}
