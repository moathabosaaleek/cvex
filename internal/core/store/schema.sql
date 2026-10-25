-- Items from every source live in one table, discriminated by kind, so the
-- feed is a single ordered query rather than a merge across tables.
CREATE TABLE IF NOT EXISTS items (
    id          TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    external_id TEXT NOT NULL,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    published   INTEGER,
    fetched     INTEGER NOT NULL,
    starred     INTEGER NOT NULL DEFAULT 0,
    raw         BLOB,
    UNIQUE (source, external_id)
);

CREATE INDEX IF NOT EXISTS items_published_idx ON items (published DESC);
CREATE INDEX IF NOT EXISTS items_kind_idx ON items (kind);

-- Entities are the graph. A CVE named in a news story and the CVE record
-- itself resolve to the same row, which is what makes "everything about
-- CVE-2026-1234" a single join rather than a text search.
CREATE TABLE IF NOT EXISTS entities (
    id    INTEGER PRIMARY KEY,
    kind  TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS item_entities (
    item_id   TEXT    NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    entity_id INTEGER NOT NULL REFERENCES entities (id) ON DELETE CASCADE,
    PRIMARY KEY (item_id, entity_id)
);

CREATE INDEX IF NOT EXISTS item_entities_entity_idx ON item_entities (entity_id);

-- CISA Known Exploited Vulnerabilities. Kept separate from items so a news
-- story mentioning a CVE can be scored against KEV membership cheaply.
CREATE TABLE IF NOT EXISTS kev (
    cve        TEXT PRIMARY KEY,
    date_added INTEGER,
    ransomware INTEGER NOT NULL DEFAULT 0
);

-- Exploit Prediction Scoring System, refreshed daily.
CREATE TABLE IF NOT EXISTS epss (
    cve        TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL,
    updated    INTEGER NOT NULL
);

-- Conditional-request state per source, so repeat fetches stay cheap and
-- polite. Feeds re-serve the same bytes indefinitely.
CREATE TABLE IF NOT EXISTS source_state (
    source        TEXT PRIMARY KEY,
    etag          TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    last_fetch    INTEGER NOT NULL DEFAULT 0
);
