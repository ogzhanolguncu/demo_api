CREATE TABLE IF NOT EXISTS counters (
  name text PRIMARY KEY,
  value bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Vitess (MySQL), run on test-vitess:
-- CREATE TABLE IF NOT EXISTS counters (
--   name varchar(255) PRIMARY KEY,
--   value bigint NOT NULL DEFAULT 0,
--   updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
-- );
