-- +goose Up
ALTER TABLE events ADD COLUMN nonce text NULL;
CREATE INDEX events_nonce_idx ON events (api_key_id, nonce, created_at) WHERE nonce IS NOT NULL;
CREATE TABLE widget_reports (
    id          char(26) PRIMARY KEY,
    api_key_id  uuid NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    nonce       text NOT NULL,
    thumbmark   text NOT NULL DEFAULT '',
    client_hash text NOT NULL DEFAULT '',
    ip          inet NULL,
    ip_hash     text NOT NULL DEFAULT '',
    ja4         text NOT NULL DEFAULT '',
    h2fp        text NOT NULL DEFAULT '',
    user_agent  text NOT NULL DEFAULT '',
    components  jsonb NULL,
    created_at  timestamptz NOT NULL
);
CREATE INDEX widget_reports_key_nonce_idx ON widget_reports (api_key_id, nonce, created_at);
CREATE INDEX widget_reports_created_idx ON widget_reports (created_at);
-- +goose Down
DROP TABLE widget_reports;
DROP INDEX events_nonce_idx;
ALTER TABLE events DROP COLUMN nonce;
