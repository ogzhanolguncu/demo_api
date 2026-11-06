CREATE TABLE IF NOT EXISTS visits (
  id bigserial PRIMARY KEY,
  path text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
