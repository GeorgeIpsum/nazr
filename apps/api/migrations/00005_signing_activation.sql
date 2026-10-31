-- +goose Up
ALTER TABLE signing_keys ADD COLUMN activates_at timestamptz NOT NULL DEFAULT now();
-- Keys that predate the column keep their creation time as activation time.
UPDATE signing_keys SET activates_at = created_at;
-- +goose Down
ALTER TABLE signing_keys DROP COLUMN activates_at;
