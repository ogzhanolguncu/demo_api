CREATE TABLE IF NOT EXISTS visits (
  id bigserial PRIMARY KEY,
  who text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
