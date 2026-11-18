-- Postgres and Neki
CREATE TABLE IF NOT EXISTS notes (
  id bigserial PRIMARY KEY,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Vitess (MySQL):
-- CREATE TABLE IF NOT EXISTS notes (
--   id bigint AUTO_INCREMENT PRIMARY KEY,
--   body text NOT NULL,
--   created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
-- );
