# PlanetScale demo

`./demo.sh` runs every command below and pauses between steps. It asks for
the migration URL without showing it. Run `./demo.sh reset` first to drop every
table from an earlier run. Needs `jq`, and `psql` or Docker.

To run the commands by hand, set `H` to the app's host first:

```bash
H=https://my-project-demo-api-local.unkey.local
```

The project has three databases: `kebap-rotate` (Postgres, prefix
`DATABASE`), `oz-vitess-test` (Vitess, prefix `OZ_VITESS_TEST`) and
`kebap-neki` (Neki, prefix `NEKI`).

## 1. Databases page (2 min)

- Each card shows the engine icon. The panel shows Activity, size and monthly
  price, Slow queries, Open SQL console.
- Warnings appear when CPU stays above 90% for an hour or storage passes 85%.
- Create database: the prefix field on Review. `DATABASE` gives
  `DATABASE_URL`, which most ORMs read.

## 2. Connect the app (2 min)

On the app's Connections page, connect production to all three databases.
On `kebap-rotate`, turn on the read-only URL. Redeploy.

## 3. One request, every database (2 min)

```bash
curl -s $H/
```

Each env var, whether Unkey set it, and what the server says. No values.

- `postgres` goes through PgBouncer, `postgres-direct` does not
- `postgres-readonly` says `"replica": true`
- `vitess` uses the `mysql://` URL, translated in `open()` in `main.go`

## 4. Least privilege and the migration URL (3 min)

```bash
curl -s -X POST $H/counters/kebap   # fails: relation "counters" does not exist
```

The app's credential reads and writes rows. It cannot create tables.

In the panel, Migrations, Get migration URL for `main`, then:

```bash
psql "$MIGRATION_URL" -f migrate.sql
curl -s -X POST $H/counters/kebap      # {"value": 1}
curl -s -X POST $H/counters/kebap      # {"value": 2}
curl -s "$H/counters?db=postgres-direct"
```

The migration URL expires on its own. Unkey shows it once and does not store
it.

## 4b. Browse data (2 min, local preview, not shipping)

In the `kebap-rotate` panel, Browse data. Open `counters`: the values the app
just wrote. The browser uses its own read-only credential, which expires in 5
minutes and is deleted on close.

## 5. Slow queries (2 min)

```bash
for i in 1 2 3; do curl -s $H/slow; done
```

Open Slow queries in the panel. The `generate_series` query is at the top of
PlanetScale Insights, and the Activity chart moves.

## 6. Rotate (1 min)

On the Connections page, rotate production on `kebap-rotate`. Redeploy, then
`curl -s $H/` again. Same output, new credential.

## 7. Questions
