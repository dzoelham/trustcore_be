CREATE TABLE IF NOT EXISTS cryptography (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  algorithm TEXT UNIQUE NOT NULL,
  category TEXT NOT NULL,
  modes TEXT NOT NULL DEFAULT '[]',               -- JSON array of strings
  test_modes TEXT NOT NULL DEFAULT '[]',          -- JSON array of strings e.g. ["KAT","MMT","MCT"]
  key_lengths TEXT NOT NULL DEFAULT '[]',         -- JSON array (bits) e.g. [128,192,256]
  block_size_bits INT,                            -- e.g. 128 for AES, 64 for TDEA/HIGHT/etc
  iv_size_bits INT,                               -- typical IV/nonce size for block modes like CBC
  standard_ref TEXT,                              -- e.g. ISO/IEC 18033-3, ISO/IEC 10118-3
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
