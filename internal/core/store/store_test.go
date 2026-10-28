package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/moathabosaaleek/cvex/internal/core/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cvex.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// A refresh re-sends every item it has ever seen, so this has to be safe to run
// repeatedly without losing local state.
func TestUpsertItemsLeavesStarredAlone(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	pub := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	it := model.Item{
		ID:         "kev:CVE-2026-1234",
		Source:     "kev",
		ExternalID: "CVE-2026-1234",
		Kind:       model.KindCVE,
		Title:      "before",
		Fetched:    time.Now().UTC(),
		Published:  &pub,
		Entities: []model.Entity{
			{Kind: model.EntityCVE, Value: "CVE-2026-1234"},
			{Kind: model.EntityVendor, Value: "Acme"},
		},
	}

	if err := s.UpsertItems(ctx, []model.Item{it}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStarred(ctx, it.ID, true); err != nil {
		t.Fatal(err)
	}

	it.Title = "after"
	if err := s.UpsertItems(ctx, []model.Item{it}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Items(ctx, model.FeedQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 item, got %d", len(got))
	}
	if got[0].Title != "after" {
		t.Errorf("title not updated, got %q", got[0].Title)
	}
	if !got[0].Starred {
		t.Error("refresh cleared starred")
	}
	if len(got[0].Entities) != 2 {
		t.Errorf("want 2 entities, got %d", len(got[0].Entities))
	}
}

func TestItemsFallBackToFetchedForOrdering(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	items := []model.Item{
		{ID: "a:1", Source: "a", ExternalID: "1", Kind: model.KindNews, Title: "2020 story", Published: &old, Fetched: now},
		{ID: "a:2", Source: "a", ExternalID: "2", Kind: model.KindNews, Title: "no date at all", Fetched: now},
	}
	if err := s.UpsertItems(ctx, items); err != nil {
		t.Fatal(err)
	}

	got, err := s.Items(ctx, model.FeedQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 items, got %d", len(got))
	}

	// The undated item was fetched seconds ago, so it should beat a 2020 story
	// rather than sinking to the bottom on a zero timestamp.
	if got[0].ID != "a:2" {
		t.Errorf("want a:2 first, got %s", got[0].ID)
	}
	if got[0].Published != nil {
		t.Error("a:2 should have no published date")
	}
	if got[1].Published == nil || !got[1].Published.Equal(old) {
		t.Errorf("published date did not round-trip: %v", got[1].Published)
	}
}

func TestKEVAndEPSSLookups(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	added := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	err := s.UpsertKEV(ctx, []model.KEVEntry{
		{CVE: "CVE-2026-1", DateAdded: &added, Ransomware: true},
		{CVE: "CVE-2026-2", DateAdded: &added},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = s.UpsertEPSS(ctx, []model.EPSSScore{
		{CVE: "CVE-2026-1", Score: 0.87, Percentile: 0.99},
	})
	if err != nil {
		t.Fatal(err)
	}

	kev, err := s.KEV(ctx, []string{"CVE-2026-1", "CVE-2026-9"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kev) != 1 {
		t.Fatalf("want 1 kev hit, got %d", len(kev))
	}
	if !kev["CVE-2026-1"].Ransomware {
		t.Error("ransomware flag lost")
	}
	if kev["CVE-2026-1"].DateAdded == nil {
		t.Error("date_added lost")
	}

	epss, err := s.EPSS(ctx, []string{"CVE-2026-1", "CVE-2026-2"})
	if err != nil {
		t.Fatal(err)
	}
	if got := epss["CVE-2026-1"]; got != 0.87 {
		t.Errorf("want 0.87, got %v", got)
	}
	if _, ok := epss["CVE-2026-2"]; ok {
		t.Error("CVE-2026-2 has no score and should not be in the map")
	}
}

func TestSourceStateRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	empty, err := s.SourceState(ctx, "kev")
	if err != nil {
		t.Fatal(err)
	}
	if empty.ETag != "" {
		t.Errorf("unseen source should come back blank, got %q", empty.ETag)
	}

	if err := s.SetSourceState(ctx, "kev", SourceState{ETag: `W/"abc123"`}); err != nil {
		t.Fatal(err)
	}

	got, err := s.SourceState(ctx, "kev")
	if err != nil {
		t.Fatal(err)
	}
	if got.ETag != `W/"abc123"` {
		t.Errorf("etag did not round-trip, got %q", got.ETag)
	}
	if got.LastFetch.IsZero() {
		t.Error("last_fetch not recorded")
	}
}

// A bad WHERE here doesn't error, it just returns nothing, which would show up
// much later as an empty feed in the UI.
func TestItemsFilters(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	hourAgo := now.Add(-time.Hour)
	lastMonth := now.AddDate(0, 0, -30)

	items := []model.Item{
		{ID: "kev:CVE-2026-1", Source: "kev", ExternalID: "CVE-2026-1", Kind: model.KindCVE,
			Title: "Acme Gateway unauthenticated RCE", Published: &now, Fetched: now},
		{ID: "krebs:1", Source: "krebs", ExternalID: "1", Kind: model.KindNews,
			Title: "Ransomware crew hits hospital", Summary: "Acme Gateway was the way in",
			Published: &hourAgo, Fetched: now},
		{ID: "krebs:2", Source: "krebs", ExternalID: "2", Kind: model.KindNews,
			Title: "Something from last month", Published: &lastMonth, Fetched: lastMonth},
	}
	if err := s.UpsertItems(ctx, items); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStarred(ctx, "krebs:2", true); err != nil {
		t.Fatal(err)
	}

	ids := func(t *testing.T, q model.FeedQuery) []string {
		t.Helper()
		got, err := s.Items(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(got))
		for i, it := range got {
			out[i] = it.ID
		}
		return out
	}

	t.Run("kind", func(t *testing.T) {
		got := ids(t, model.FeedQuery{Kinds: []model.Kind{model.KindCVE}})
		if len(got) != 1 || got[0] != "kev:CVE-2026-1" {
			t.Errorf("want just the cve, got %v", got)
		}
	})

	t.Run("search covers summary", func(t *testing.T) {
		// "Acme Gateway" sits in one title and one summary, so this fails if
		// the query only looks at titles.
		if got := ids(t, model.FeedQuery{Search: "Acme Gateway"}); len(got) != 2 {
			t.Errorf("want both, got %v", got)
		}
	})

	t.Run("starred only", func(t *testing.T) {
		got := ids(t, model.FeedQuery{StarredOnly: true})
		if len(got) != 1 || got[0] != "krebs:2" {
			t.Errorf("want krebs:2, got %v", got)
		}
	})

	t.Run("since", func(t *testing.T) {
		cutoff := now.AddDate(0, 0, -1)
		if got := ids(t, model.FeedQuery{Since: &cutoff}); len(got) != 2 {
			t.Errorf("want the two recent items, got %v", got)
		}
	})

	t.Run("limit and offset", func(t *testing.T) {
		first := ids(t, model.FeedQuery{Limit: 1})
		second := ids(t, model.FeedQuery{Limit: 1, Offset: 1})
		if len(first) != 1 || len(second) != 1 {
			t.Fatalf("want one row each, got %v and %v", first, second)
		}
		if first[0] != "kev:CVE-2026-1" {
			t.Errorf("newest should come first, got %s", first[0])
		}
		if second[0] == first[0] {
			t.Errorf("offset returned the same row: %s", second[0])
		}
	})

	t.Run("filters combine", func(t *testing.T) {
		got := ids(t, model.FeedQuery{
			Kinds:  []model.Kind{model.KindNews},
			Search: "Acme",
		})
		if len(got) != 1 || got[0] != "krebs:1" {
			t.Errorf("want krebs:1, got %v", got)
		}
	})
}
