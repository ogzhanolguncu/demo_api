#!/usr/bin/env bash
# PlanetScale demo. Run ./demo.sh help for the commands.
set -euo pipefail
command -v jq >/dev/null || { echo "demo.sh needs jq: brew install jq"; exit 1; }

DIR="$(cd "$(dirname "$0")" && pwd)"
H="${H:-https://my-project-demo-api-local.unkey.local}"

bold=$'\e[1m'; dim=$'\e[2m'; reset=$'\e[0m'

step() { printf '\n%s== %s ==%s\n' "$bold" "$1" "$reset"; }
note() { printf '%s%s%s\n' "$dim" "$1" "$reset"; }
pause() { read -r -p "${dim}[enter]${reset} " _ </dev/tty; }
show() {
  printf '%s$ curl -s %s%s\n' "$dim" "${*:2}" "$reset"
  local body
  body="$("$@")"
  if jq -e . >/dev/null 2>&1 <<<"$body"; then jq . <<<"$body"; else echo "$body"; fi
}
api() { curl -sk --max-time 60 "$@"; }

status() { show api "$H/"; }
inc() { show api -X POST "$H/counters/${1:-kebap}"; }
counters() { show api "$H/counters?db=${1:-postgres}"; }
slow() { for _ in $(seq "${1:-3}"); do show api "$H/slow"; done; }
readonly_set() {
  api "$H/" | jq -e '.[] | select(.env == "DATABASE_READONLY_URL" and .set)' >/dev/null
}

# Runs SQL from stdin with a migration URL read from the terminal, never echoed.
run_sql() {
  local url="${MIGRATION_URL:-}"
  if [[ -z "$url" ]]; then
    note "Panel > Migrations > Get migration URL on main. Paste it here, it is not shown."
    read -r -s -p "Migration URL: " url </dev/tty
    echo
  fi
  [[ -n "$url" ]] || { echo "no migration URL given"; exit 1; }
  # libpq has no default trust store; verify-full needs to be told to use the system one.
  [[ "$url" == *sslrootcert=* ]] || url="$url&sslrootcert=system"
  if command -v psql >/dev/null; then
    psql "$url"
  else
    docker run --rm -i postgres:18-alpine psql "$url"
  fi
}
migrate() { run_sql < "$DIR/migrate.sql"; }
# Drops every table in public, so the demo starts from an empty database.
reset_db() {
  run_sql <<'SQL'
DO $$
DECLARE t record;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    RAISE NOTICE 'dropping %', t.tablename;
    EXECUTE format('DROP TABLE public.%I CASCADE', t.tablename);
  END LOOP;
END $$;
SQL
}

walkthrough() {
  step "1. One app, every database"
  note "Each env var Unkey wrote, whether it is set, and what the server says. No values."
  status
  pause

  step "2. The app cannot create tables"
  note "Unkey gives the app a role that reads and writes rows, nothing more."
  inc kebap
  pause

  step "3. Migrate with a short-lived migration URL"
  migrate
  pause

  step "4. Write and read through the app"
  note "Same credential as step 2, no redeploy. Now it works."
  inc kebap
  inc kebap
  inc kebap
  inc demo
  note "Through the direct URL, the same values:"
  counters postgres-direct
  if readonly_set; then
    note "Through the read-only URL, from a replica:"
    counters postgres-readonly
  fi
  pause

  step "5. Browse data (local preview, not shipping)"
  note "Open the kebap-rotate panel > Browse data > counters. kebap is 3, demo is 1."
  pause

  step "6. Slow queries"
  note "A deliberately expensive query, three times. Then open Slow queries in the panel."
  slow 3
  pause

  step "7. Rotate"
  note "Connections page > rotate production on kebap-rotate > redeploy. Press enter when it is live."
  pause
  status

  step "Done"
}

usage() {
  cat <<EOF
./demo.sh               the guided walkthrough, pauses between steps
./demo.sh status        every database, set or not, what the server says
./demo.sh inc [name]    add 1 to a counter (default: kebap)
./demo.sh counters [db] list counters: postgres (default), postgres-direct,
                        postgres-readonly, neki
./demo.sh slow [n]      run the expensive query n times (default 3)
./demo.sh migrate       create the counters table (asks for a migration URL)
./demo.sh reset         drop every table in public (asks for a migration URL)

Host: $H  (override with H=...)
migrate and reset take MIGRATION_URL=... instead of the prompt.
EOF
}

case "${1:-}" in
  "") walkthrough ;;
  status) status ;;
  inc) inc "${2:-}" ;;
  counters) counters "${2:-}" ;;
  slow) slow "${2:-}" ;;
  migrate) migrate ;;
  reset) reset_db ;;
  help | -h | --help) usage ;;
  *) usage; exit 1 ;;
esac
