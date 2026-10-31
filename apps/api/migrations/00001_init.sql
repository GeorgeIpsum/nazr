-- +goose Up
CREATE TABLE api_keys (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash              text NOT NULL UNIQUE,
    prefix                text NOT NULL,
    label                 text NOT NULL DEFAULT '',
    allowed_origins       text[] NOT NULL DEFAULT '{}',
    rate_limit_per_minute integer NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    revoked_at            timestamptz NULL,
    last_used_at          timestamptz NULL,
    -- RecordVisit reads the per-key visitor total from this counter instead of
    -- count(*) over visitors, which grows with the table. CreateVisitor keeps
    -- it current in the same statement as the insert.
    visitor_count         bigint NOT NULL DEFAULT 0
);

CREATE TABLE visitors (
    id            char(26) PRIMARY KEY,
    api_key_id    uuid NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    first_seen    timestamptz NOT NULL,
    last_seen     timestamptz NOT NULL,
    request_count bigint NOT NULL DEFAULT 0
);
CREATE INDEX visitors_api_key_idx ON visitors (api_key_id);

CREATE TABLE visitor_thumbmarks (
    api_key_id uuid NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    visitor_id char(26) NOT NULL REFERENCES visitors (id) ON DELETE CASCADE,
    thumbmark  text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    count      bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (visitor_id, thumbmark)
);
CREATE INDEX visitor_thumbmarks_lookup_idx ON visitor_thumbmarks (api_key_id, thumbmark, last_seen DESC);

CREATE TABLE thumbmark_counts (
    api_key_id        uuid NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    thumbmark         text NOT NULL,
    distinct_visitors bigint NOT NULL,
    PRIMARY KEY (api_key_id, thumbmark)
);

CREATE TABLE events (
    id             char(26) PRIMARY KEY,
    api_key_id     uuid NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    visitor_id     char(26) NOT NULL,
    thumbmark      text NOT NULL,
    client_hash    text NOT NULL DEFAULT '',
    ip             inet NULL,
    ip_hash        text NOT NULL DEFAULT '',
    ja4            text NOT NULL DEFAULT '',
    ja4h           text NOT NULL DEFAULT '',
    h2fp           text NOT NULL DEFAULT '',
    user_agent     text NOT NULL DEFAULT '',
    path           text NOT NULL DEFAULT '',
    classification jsonb NULL,
    signals        jsonb NULL,
    components     jsonb NULL,
    metadata       jsonb NULL,
    -- The JA3 hash hashes the wire order of the TLS extensions, which Chromium
    -- permutes on every connection, so it is not part of the tls component
    -- (and so not of the thumbmark). It is kept on the event for analysis;
    -- NULL when no ClientHello was captured.
    ja3_hash       char(32) NULL,
    canvas_probe   text NULL,
    cohort         text NULL,
    created_at     timestamptz NOT NULL
);
CREATE INDEX events_key_created_idx ON events (api_key_id, created_at);
CREATE INDEX events_visitor_idx ON events (visitor_id);
CREATE INDEX events_created_idx ON events (created_at);
-- Serves store.HasRecentEvent (the /beacon poisoning check).
CREATE INDEX events_thumbmark_created_idx ON events (thumbmark, created_at);
CREATE INDEX events_probe_cohort_idx ON events (api_key_id, cohort, created_at);

CREATE TABLE ua_ja4_observations (
    ja4        text NOT NULL,
    ua_family  text NOT NULL,
    count      bigint NOT NULL DEFAULT 1,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    PRIMARY KEY (ja4, ua_family)
);

CREATE TABLE client_logs (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    api_key_id uuid NULL REFERENCES api_keys (id) ON DELETE SET NULL,
    body       jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX client_logs_created_idx ON client_logs (created_at);

CREATE TABLE list_state (
    name          text PRIMARY KEY,
    last_modified text NOT NULL DEFAULT '',
    etag          text NOT NULL DEFAULT '',
    fetched_at    timestamptz NOT NULL,
    row_count     bigint NOT NULL DEFAULT 0
);

-- +goose Down
DROP TABLE list_state, client_logs, ua_ja4_observations, events,
    thumbmark_counts, visitor_thumbmarks, visitors, api_keys;
