-- +goose Up
-- RecordVisit reads the per-key visitor total from this counter instead of
-- count(*) over visitors, which grows with the table. CreateVisitor keeps it
-- current in the same statement as the insert.
ALTER TABLE api_keys ADD COLUMN visitor_count bigint NOT NULL DEFAULT 0;
UPDATE api_keys SET visitor_count = (SELECT count(*) FROM visitors v WHERE v.api_key_id = api_keys.id);

-- +goose Down
ALTER TABLE api_keys DROP COLUMN visitor_count;
