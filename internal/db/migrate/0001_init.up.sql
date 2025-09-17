-- 0001_init.up.sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS roles (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, role_id)
);

CREATE TABLE IF NOT EXISTS vectors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  algorithm TEXT NOT NULL,
  params JSONB NOT NULL DEFAULT '{}'::jsonb,
  input_hex TEXT,
  input_path TEXT,
  expected_hex TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  vector_id UUID REFERENCES vectors(id),
  uploaded_hex TEXT,
  uploaded_path TEXT,
  is_match BOOLEAN,
  mismatch_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  action TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO roles(name) VALUES ('Administrator') ON CONFLICT DO NOTHING;
INSERT INTO roles(name) VALUES ('User') ON CONFLICT DO NOTHING;
