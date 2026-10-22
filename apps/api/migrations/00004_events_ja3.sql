-- +goose Up
-- The JA3 hash hashes the wire order of the TLS extensions, which Chromium
-- permutes on every connection, so it is not part of the tls component (and
-- so not of the thumbmark). It is kept on the event for analysis; NULL when
-- no ClientHello was captured.
ALTER TABLE events ADD COLUMN ja3_hash char(32) NULL;

-- +goose Down
ALTER TABLE events DROP COLUMN ja3_hash;
