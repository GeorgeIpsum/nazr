-- +goose Up
ALTER TABLE widget_reports
    ADD COLUMN pow_ok          boolean     NOT NULL DEFAULT false,
    ADD COLUMN verdict         text        NOT NULL DEFAULT '',
    ADD COLUMN hostname        text        NOT NULL DEFAULT '',
    ADD COLUMN classification  jsonb       NULL,
    ADD COLUMN signals         jsonb       NULL,
    ADD COLUMN token_issued_at timestamptz NULL,
    ADD COLUMN verified_at     timestamptz NULL,
    ADD COLUMN replay_count    int         NOT NULL DEFAULT 0;
CREATE TABLE signing_keys (
    kid             text        PRIMARY KEY,
    private_key_pem text        NOT NULL,
    public_jwk      jsonb       NOT NULL,
    hmac_secret     bytea       NOT NULL,
    created_at      timestamptz NOT NULL,
    retired_at      timestamptz NULL
);
ALTER TABLE api_keys ADD COLUMN secret_hash text NULL, ADD COLUMN secret_prefix text NULL;
CREATE UNIQUE INDEX api_keys_secret_hash_idx ON api_keys (secret_hash) WHERE secret_hash IS NOT NULL;
-- +goose Down
DROP INDEX api_keys_secret_hash_idx;
ALTER TABLE api_keys DROP COLUMN secret_hash, DROP COLUMN secret_prefix;
DROP TABLE signing_keys;
ALTER TABLE widget_reports DROP COLUMN pow_ok, DROP COLUMN verdict, DROP COLUMN hostname, DROP COLUMN classification,
    DROP COLUMN signals, DROP COLUMN token_issued_at, DROP COLUMN verified_at, DROP COLUMN replay_count;
