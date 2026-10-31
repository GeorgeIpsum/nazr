-- +goose Up
ALTER TABLE widget_reports ADD COLUMN interaction jsonb NULL;
-- +goose Down
ALTER TABLE widget_reports DROP COLUMN interaction;
