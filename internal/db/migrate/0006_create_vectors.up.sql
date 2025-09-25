CREATE TABLE IF NOT EXISTS vectors (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL,
  client_id     UUID NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
  algorithm     TEXT NOT NULL,
  mode          TEXT NOT NULL,
  test_mode     TEXT NOT NULL,
  direction     TEXT NOT NULL,           -- ENCRYPT | DECRYPT
  input_hex     TEXT NOT NULL,
  output_hex    TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_vectors_client_user_created
  ON vectors (client_id, user_id, created_at DESC);
