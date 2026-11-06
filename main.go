package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Each database Unkey connects, by the env var it writes. The prefix is the
// one chosen when the database was added to the project.
var databases = []database{
	{name: "postgres", env: "DATABASE_URL"},
	{name: "postgres-direct", env: "DATABASE_UNPOOLED_URL"},
	{name: "postgres-readonly", env: "DATABASE_READONLY_URL"},
	{name: "neki", env: "NEKI_URL"},
	{name: "vitess", env: "OZ_VITESS_TEST_URL"},
}

type database struct {
	name string
	env  string
	db   *sql.DB
}

func main() {
	for i := range databases {
		raw := os.Getenv(databases[i].env)
		if raw == "" {
			continue
		}
		db, err := open(raw)
		if err != nil {
			log.Printf("%s: %v", databases[i].env, err)
			continue
		}
		databases[i].db = db
	}

	http.HandleFunc("GET /{$}", status)
	http.HandleFunc("POST /counters/{name}", increment)
	http.HandleFunc("GET /counters", listCounters)
	http.HandleFunc("GET /slow", slow)
	log.Fatal(http.ListenAndServe(":"+cmp.Or(os.Getenv("PORT"), "8080"), nil))
}

// Unkey writes mysql:// URLs, the form Node and Prisma clients read. The Go
// driver takes its own DSN, so the URL is translated here.
func open(raw string) (*sql.DB, error) {
	if !strings.HasPrefix(raw, "mysql://") {
		cfg, err := pgx.ParseConfig(raw)
		if err != nil {
			return nil, err
		}
		// DATABASE_URL goes through PgBouncer in transaction mode, where named
		// prepared statements from two app connections can collide.
		cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
		return stdlib.OpenDB(*cfg), nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	cfg := mysql.NewConfig()
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.Net = "tcp"
	cfg.Addr = u.Host + ":3306"
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	cfg.TLSConfig = "true"
	return sql.Open("mysql", cfg.FormatDSN())
}

type check struct {
	Database  string `json:"database"`
	Env       string `json:"env"`
	Set       bool   `json:"set"`
	Server    string `json:"server,omitempty"`
	User      string `json:"user,omitempty"`
	Replica   *bool  `json:"replica,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Lists every env var the app looks for, whether Unkey set it, and what the
// server behind it says. Values are never printed.
func status(w http.ResponseWriter, r *http.Request) {
	checks := make([]check, 0, len(databases))
	for _, d := range databases {
		c := check{Database: d.name, Env: d.env, Set: d.db != nil}
		if d.db != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			start := time.Now()
			if err := describe(ctx, d, &c); err != nil {
				c.Error = err.Error()
			}
			c.LatencyMs = time.Since(start).Milliseconds()
			cancel()
		}
		checks = append(checks, c)
	}
	writeJSON(w, http.StatusOK, checks)
}

func describe(ctx context.Context, d database, c *check) error {
	if d.name == "vitess" {
		return d.db.QueryRowContext(ctx, "SELECT version(), current_user()").Scan(&c.Server, &c.User)
	}
	var replica bool
	err := d.db.QueryRowContext(ctx, "SELECT version(), current_user, pg_is_in_recovery()").
		Scan(&c.Server, &c.User, &replica)
	c.Replica = &replica
	return err
}

// Fails until migrate.sql has run: the credential Unkey gives the app can
// read and write rows but cannot create tables.
func increment(w http.ResponseWriter, r *http.Request) {
	d, ok := pick(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	var value int64
	err := d.db.QueryRowContext(r.Context(), `
		INSERT INTO counters (name, value) VALUES ($1, 1)
		ON CONFLICT (name) DO UPDATE SET value = counters.value + 1, updated_at = now()
		RETURNING value`, name).Scan(&value)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"database": d.name, "counter": name, "value": value})
}

func listCounters(w http.ResponseWriter, r *http.Request) {
	d, ok := pick(w, r)
	if !ok {
		return
	}
	rows, err := d.db.QueryContext(r.Context(), "SELECT name, value FROM counters ORDER BY name")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	counters := map[string]int64{}
	for rows.Next() {
		var name string
		var value int64
		if err := rows.Scan(&name, &value); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		counters[name] = value
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"database": d.name, "counters": counters})
}

// A deliberately expensive query, so it shows up under Slow queries in
// PlanetScale Insights and moves the Activity chart in Unkey.
func slow(w http.ResponseWriter, r *http.Request) {
	d, ok := pick(w, r)
	if !ok {
		return
	}
	start := time.Now()
	var n int64
	if err := d.db.QueryRowContext(r.Context(), "SELECT count(*) FROM generate_series(1, 20000000)").Scan(&n); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"database": d.name, "rows": n, "took_ms": time.Since(start).Milliseconds()})
}

// ?db=postgres (default), postgres-direct, postgres-readonly or neki. Vitess
// only takes part in the status check.
func pick(w http.ResponseWriter, r *http.Request) (database, bool) {
	name := cmp.Or(r.URL.Query().Get("db"), "postgres")
	for _, d := range databases {
		if d.name != name || d.name == "vitess" {
			continue
		}
		if d.db == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": fmt.Sprintf("%s is not set", d.env)})
			return database{}, false
		}
		return d, true
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown db " + name})
	return database{}, false
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}
