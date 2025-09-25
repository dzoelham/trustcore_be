-- Ensure jsonb and new columns exist for compatibility with generate_handlers.go
DO $$ BEGIN
  PERFORM 1 FROM pg_type WHERE typname = 'jsonb';
EXCEPTION WHEN undefined_object THEN
  -- jsonb exists since PG 9.4; this block is defensive.
  RAISE NOTICE 'jsonb type should exist on modern Postgres versions';
END $$;

ALTER TABLE vectors
  ADD COLUMN IF NOT EXISTS method   TEXT,
  ADD COLUMN IF NOT EXISTS params   JSONB,
  ADD COLUMN IF NOT EXISTS status   TEXT;

-- Optional defaults (commented out; adjust if you want defaults)
-- ALTER TABLE vectors ALTER COLUMN status SET DEFAULT 'ready';
