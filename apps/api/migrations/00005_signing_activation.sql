-- +goose Up
ALTER TABLE signing_keys ADD COLUMN activates_at timestamptz NOT NULL DEFAULT now();
-- +goose Down
ALTER TABLE signing_keys DROP COLUMN activates_at;
