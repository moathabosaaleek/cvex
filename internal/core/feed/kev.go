package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/moathabosaaleek/cvex/internal/core/model"
)

// CISA's own copy sits behind an Akamai WAF that 403s depending on where you
// are and what you look like. The cisagov mirror is the same bytes, has git
// history, and its ETag actually honours If-None-Match, which cisa.gov's does
// not.
const kevMirrorURL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

// KEV is the CISA Known Exploited Vulnerabilities catalogue. It's the best
// single source to start from: one small JSON file, no key, and every entry is
// something attackers are actually using rather than a theoretical 9.8.
type KEV struct {
	URL string
	UA  string
}

func DefaultKEV() KEV {
	return KEV{URL: kevMirrorURL}
}

func (KEV) Name() string { return "kev" }

// Entries stay as RawMessage so the bytes we store are the bytes CISA sent.
// Marshalling kevRecord back out would quietly drop every field we don't model
// yet, and the mirror only serves the current catalogue, so anything lost that
// way is lost for good.
type kevPayload struct {
	CatalogVersion  string            `json:"catalogVersion"`
	DateReleased    string            `json:"dateReleased"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

type kevRecord struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`

	// Strings, not bools: "Known" or "Unknown".
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`

	// "Yes" or "No". Yes means CISA thinks you should assume compromise and go
	// looking. Captured but not scored yet.
	ForensicTriage string `json:"forensicTriage"`

	// Usually one or more advisory URLs, occasionally prose.
	Notes string `json:"notes"`

	CWEs []string `json:"cwes"`
}

func (k KEV) Collect(ctx context.Context, f *Fetcher, prev Conditional) (Result, error) {
	resp, err := f.getAs(ctx, k.URL, k.UA, prev)
	if err != nil {
		return Result{}, err
	}
	if resp.notModified {
		return Result{Unchanged: true, Next: prev}, nil
	}

	var payload kevPayload
	if err := json.Unmarshal(resp.body, &payload); err != nil {
		return Result{}, fmt.Errorf("decode kev: %w", err)
	}
	if len(payload.Vulnerabilities) == 0 {
		return Result{}, fmt.Errorf("kev catalogue %q had no entries", payload.CatalogVersion)
	}

	now := time.Now().UTC()
	out := Result{
		Next:  Conditional{ETag: resp.etag, LastModified: resp.lastModified},
		Items: make([]model.Item, 0, len(payload.Vulnerabilities)),
		KEV:   make([]model.KEVEntry, 0, len(payload.Vulnerabilities)),
	}

	undated := 0
	for _, raw := range payload.Vulnerabilities {
		var v kevRecord
		if err := json.Unmarshal(raw, &v); err != nil {
			return Result{}, fmt.Errorf("decode kev entry: %w", err)
		}

		// Upper-cased to match what ExtractCVEs does to ids it scrapes out of
		// news text. entities is UNIQUE on (kind, value) and SQLite compares
		// case-sensitively, so one stray lowercase id here would quietly create
		// a second node and break the join the whole design rests on.
		cve := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if cve == "" {
			continue
		}

		added := parseKEVDate(v.DateAdded)
		if added == nil {
			undated++
		}

		entities := []model.Entity{{Kind: model.EntityCVE, Value: cve}}
		if v.VendorProject != "" {
			entities = append(entities, model.Entity{Kind: model.EntityVendor, Value: v.VendorProject})
		}
		if v.Product != "" {
			entities = append(entities, model.Entity{Kind: model.EntityProduct, Value: v.Product})
		}
		for _, cwe := range v.CWEs {
			entities = append(entities, model.Entity{Kind: model.EntityCWE, Value: cwe})
		}

		out.Items = append(out.Items, model.Item{
			ID:         itemID(k.Name(), cve),
			Source:     k.Name(),
			ExternalID: cve,
			Kind:       model.KindCVE,
			Title:      kevTitle(cve, v.VendorProject, v.Product, v.VulnerabilityName),
			Summary:    v.ShortDescription,
			URL:        linkFor(cve, v.Notes),
			Published:  added,
			Fetched:    now,
			Entities:   entities,
			Raw:        raw,
		})

		out.KEV = append(out.KEV, model.KEVEntry{
			CVE: cve,
			// Its own copy. Sharing one pointer with Item.Published means a
			// consumer normalising a date in place silently rewrites this too.
			DateAdded:  copyTime(added),
			Ransomware: v.KnownRansomwareCampaignUse == "Known",
		})
	}

	// Decoding can succeed on a renamed field and leave every record empty, so
	// the count check above is not enough on its own. Without this, a schema
	// change returns a successful empty Result, the caller stores the fresh
	// ETag, and every poll after it 304s. The feed would report that nothing on
	// earth is being exploited, permanently, with no error anywhere.
	if len(out.Items) == 0 {
		return Result{}, fmt.Errorf("kev catalogue %q: %d entries, none with a cveID",
			payload.CatalogVersion, len(payload.Vulnerabilities))
	}
	if undated == len(out.Items) {
		return Result{}, fmt.Errorf("kev catalogue %q: dateAdded parsed on none of %d entries",
			payload.CatalogVersion, len(out.Items))
	}

	return out, nil
}

// Stops at the characters that usually sit around a URL in prose rather than
// inside one. KEV notes wrap links in parentheses often enough to matter.
var linkRE = regexp.MustCompile(`https?://[^\s<>"')\]]+`)

// KEV entries have no link field. notes usually holds a vendor advisory, which
// beats a generic NVD page, so take the first URL out of it when there is one.
func linkFor(cve, notes string) string {
	if u := linkRE.FindString(notes); u != "" {
		return strings.TrimRight(u, ".,;:")
	}
	return "https://nvd.nist.gov/vuln/detail/" + cve
}

func kevTitle(cve, vendor, product, name string) string {
	if vendor != "" && product != "" {
		return fmt.Sprintf("%s  %s %s: %s", cve, vendor, product, name)
	}
	return cve + "  " + name
}

func parseKEVDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}
