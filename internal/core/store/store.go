// Package store is the only place that knows SQL.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/moathabosaaleek/cvex/internal/core/model"
)

//go:embed schema.sql
var schema string

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// WAL lets a collector write while the TUI reads. busy_timeout matters more
	// than it looks: without it, a concurrent write returns SQLITE_BUSY straight
	// away instead of waiting.
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// UpsertItems runs on every refresh, so it has to leave starred and fetched
// alone on rows that already exist. Feeds re-serve the same entries forever.
func (s *Store) UpsertItems(ctx context.Context, items []model.Item) error {
	if len(items) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	ins, err := tx.PrepareContext(ctx, `
		INSERT INTO items (id, source, external_id, kind, title, summary, url, published, fetched, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			title     = excluded.title,
			summary   = excluded.summary,
			url       = excluded.url,
			published = excluded.published,
			raw       = excluded.raw`)
	if err != nil {
		return err
	}
	defer ins.Close()

	for _, it := range items {
		_, err := ins.ExecContext(ctx, it.ID, it.Source, it.ExternalID, string(it.Kind),
			it.Title, it.Summary, it.URL, unixOrNil(it.Published), it.Fetched.Unix(), it.Raw)
		if err != nil {
			return fmt.Errorf("upsert %s: %w", it.ID, err)
		}
		if err := linkEntities(ctx, tx, it); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func linkEntities(ctx context.Context, tx *sql.Tx, it model.Item) error {
	for _, e := range it.Entities {
		// The no-op DO UPDATE is deliberate: plain DO NOTHING suppresses
		// RETURNING on conflict, so there'd be no id to link against.
		var id int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO entities (kind, value) VALUES (?, ?)
			ON CONFLICT (kind, value) DO UPDATE SET value = excluded.value
			RETURNING id`, string(e.Kind), e.Value).Scan(&id)
		if err != nil {
			return fmt.Errorf("entity %s=%s: %w", e.Kind, e.Value, err)
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO item_entities (item_id, entity_id) VALUES (?, ?)
			ON CONFLICT DO NOTHING`, it.ID, id)
		if err != nil {
			return err
		}
	}
	return nil
}

// Items returns the feed without scoring it. Scores depend on KEV and EPSS,
// which are separate lookups, and keeping them out of here keeps the ranking
// testable without a database.
func (s *Store) Items(ctx context.Context, q model.FeedQuery) ([]model.Item, error) {
	where := []string{"1 = 1"}
	var args []any

	if len(q.Kinds) > 0 {
		where = append(where, "kind IN ("+placeholders(len(q.Kinds))+")")
		for _, k := range q.Kinds {
			args = append(args, string(k))
		}
	}
	if q.StarredOnly {
		where = append(where, "starred = 1")
	}
	if q.Since != nil {
		where = append(where, "COALESCE(published, fetched) >= ?")
		args = append(args, q.Since.Unix())
	}
	if q.Search != "" {
		// TODO: FTS5. LIKE is instant up to a few tens of thousands of rows and
		// it's one less thing to get wrong while the schema is still moving.
		where = append(where, "(title LIKE ? OR summary LIKE ?)")
		pat := "%" + q.Search + "%"
		args = append(args, pat, pat)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}

	// COALESCE so items with no published date fall back to when we saw them,
	// rather than sinking to the bottom forever.
	query := `
		SELECT id, source, external_id, kind, title, summary, url, published, fetched, starred
		FROM items
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY COALESCE(published, fetched) DESC
		LIMIT ? OFFSET ?`
	args = append(args, limit, q.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.Item
	for rows.Next() {
		var (
			it      model.Item
			kind    string
			pub     sql.NullInt64
			fetched int64
		)
		err := rows.Scan(&it.ID, &it.Source, &it.ExternalID, &kind, &it.Title,
			&it.Summary, &it.URL, &pub, &fetched, &it.Starred)
		if err != nil {
			return nil, err
		}
		it.Kind = model.Kind(kind)
		it.Fetched = time.Unix(fetched, 0).UTC()
		if pub.Valid {
			t := time.Unix(pub.Int64, 0).UTC()
			it.Published = &t
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := s.attachEntities(ctx, items); err != nil {
		return nil, err
	}
	return items, nil
}

// attachEntities does a second pass rather than joining in Items. The join
// version fans out to one row per entity and the deduplication of that was
// worse than just asking twice.
func (s *Store) attachEntities(ctx context.Context, items []model.Item) error {
	if len(items) == 0 {
		return nil
	}

	byID := make(map[string]*model.Item, len(items))
	args := make([]any, 0, len(items))
	for i := range items {
		byID[items[i].ID] = &items[i]
		args = append(args, items[i].ID)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT ie.item_id, e.kind, e.value
		FROM item_entities ie
		JOIN entities e ON e.id = ie.entity_id
		WHERE ie.item_id IN (`+placeholders(len(items))+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var itemID, kind, value string
		if err := rows.Scan(&itemID, &kind, &value); err != nil {
			return err
		}
		if it := byID[itemID]; it != nil {
			it.Entities = append(it.Entities, model.Entity{
				Kind:  model.EntityKind(kind),
				Value: value,
			})
		}
	}
	return rows.Err()
}

func (s *Store) SetStarred(ctx context.Context, id string, on bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE items SET starred = ? WHERE id = ?`, on, id)
	return err
}

func (s *Store) UpsertKEV(ctx context.Context, entries []model.KEVEntry) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO kev (cve, date_added, ransomware) VALUES (?, ?, ?)
			ON CONFLICT (cve) DO UPDATE SET
				date_added = excluded.date_added,
				ransomware = excluded.ransomware`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, e := range entries {
			if _, err := stmt.ExecContext(ctx, e.CVE, unixOrNil(e.DateAdded), e.Ransomware); err != nil {
				return fmt.Errorf("kev %s: %w", e.CVE, err)
			}
		}
		return nil
	})
}

func (s *Store) UpsertEPSS(ctx context.Context, scores []model.EPSSScore) error {
	now := time.Now().Unix()
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO epss (cve, score, percentile, updated) VALUES (?, ?, ?, ?)
			ON CONFLICT (cve) DO UPDATE SET
				score      = excluded.score,
				percentile = excluded.percentile,
				updated    = excluded.updated`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, sc := range scores {
			if _, err := stmt.ExecContext(ctx, sc.CVE, sc.Score, sc.Percentile, now); err != nil {
				return fmt.Errorf("epss %s: %w", sc.CVE, err)
			}
		}
		return nil
	})
}

func (s *Store) KEV(ctx context.Context, cves []string) (map[string]model.KEVEntry, error) {
	out := make(map[string]model.KEVEntry)
	if len(cves) == 0 {
		return out, nil
	}

	args := toAny(cves)
	rows, err := s.db.QueryContext(ctx,
		`SELECT cve, date_added, ransomware FROM kev WHERE cve IN (`+placeholders(len(cves))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			e     model.KEVEntry
			added sql.NullInt64
		)
		if err := rows.Scan(&e.CVE, &added, &e.Ransomware); err != nil {
			return nil, err
		}
		if added.Valid {
			t := time.Unix(added.Int64, 0).UTC()
			e.DateAdded = &t
		}
		out[e.CVE] = e
	}
	return out, rows.Err()
}

func (s *Store) EPSS(ctx context.Context, cves []string) (map[string]float64, error) {
	out := make(map[string]float64)
	if len(cves) == 0 {
		return out, nil
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT cve, score FROM epss WHERE cve IN (`+placeholders(len(cves))+`)`, toAny(cves)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cve   string
			score float64
		)
		if err := rows.Scan(&cve, &score); err != nil {
			return nil, err
		}
		out[cve] = score
	}
	return out, rows.Err()
}

// SourceState carries the conditional-request headers from the last fetch.
type SourceState struct {
	ETag         string
	LastModified string
	LastFetch    time.Time
}

func (s *Store) SourceState(ctx context.Context, source string) (SourceState, error) {
	var (
		st    SourceState
		fetch int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT etag, last_modified, last_fetch FROM source_state WHERE source = ?`,
		source).Scan(&st.ETag, &st.LastModified, &fetch)
	if errors.Is(err, sql.ErrNoRows) {
		return SourceState{}, nil
	}
	if err != nil {
		return SourceState{}, err
	}
	st.LastFetch = time.Unix(fetch, 0).UTC()
	return st, nil
}

func (s *Store) SetSourceState(ctx context.Context, source string, st SourceState) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO source_state (source, etag, last_modified, last_fetch) VALUES (?, ?, ?, ?)
		ON CONFLICT (source) DO UPDATE SET
			etag          = excluded.etag,
			last_modified = excluded.last_modified,
			last_fetch    = excluded.last_fetch`,
		source, st.ETag, st.LastModified, time.Now().Unix())
	return err
}

func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func unixOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}
