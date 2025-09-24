ALTER TABLE clients
  DROP COLUMN IF EXISTS product_name,
  DROP COLUMN IF EXISTS product_version;
