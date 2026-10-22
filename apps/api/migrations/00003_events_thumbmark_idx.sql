-- +goose Up
-- Serves store.HasRecentEvent (the /beacon poisoning check).
CREATE INDEX events_thumbmark_created_idx ON events (thumbmark, created_at);

-- +goose Down
DROP INDEX events_thumbmark_created_idx;
