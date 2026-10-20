package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A counter API on the database that Unkey attaches to the app. It reads
// DATABASE_URL lazily, so the app still starts when the variable is missing.

const createCountersTable = `CREATE TABLE IF NOT EXISTS counters (
	name       text PRIMARY KEY,
	value      bigint NOT NULL DEFAULT 0,
	updated_at timestamptz NOT NULL DEFAULT now()
)`

type store struct {
	mu    sync.Mutex
	pool  *pgxpool.Pool
	ready bool
}

func (s *store) get(ctx context.Context) (*pgxpool.Pool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		url := os.Getenv("DATABASE_URL")
		if url == "" {
			return nil, errors.New("DATABASE_URL is not set")
		}
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			return nil, err
		}
		s.pool = pool
	}
	if !s.ready {
		if _, err := s.pool.Exec(ctx, createCountersTable); err != nil {
			return nil, err
		}
		s.ready = true
	}
	return s.pool, nil
}

type counter struct {
	Name      string    `json:"name"`
	Value     int64     `json:"value"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func dbError(w http.ResponseWriter, err error) {
	slog.Error("database request failed", "error", err)
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	db := &store{}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"routes": []string{
			"GET /ping",
			"GET /counters",
			"GET /counters/{name}",
			"POST /counters/{name}/increment",
			"DELETE /counters/{name}",
		}})
	})

	// Shows who the app connects as and what that role may do, without
	// creating the counters table first.
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
		url := os.Getenv("DATABASE_URL")
		if url == "" {
			dbError(w, errors.New("DATABASE_URL is not set"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, url)
		if err != nil {
			dbError(w, err)
			return
		}
		defer conn.Close(ctx)
		var user, database, version string
		var canCreate, canRead, canWrite bool
		err = conn.QueryRow(ctx, `SELECT current_user, current_database(), version(),
			has_schema_privilege('public', 'CREATE'),
			pg_has_role(current_user, 'pg_read_all_data', 'MEMBER'),
			pg_has_role(current_user, 'pg_write_all_data', 'MEMBER')`).
			Scan(&user, &database, &version, &canCreate, &canRead, &canWrite)
		if err != nil {
			dbError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user":                    user,
			"database":                database,
			"version":                 version,
			"canCreateTablesInPublic": canCreate,
			"memberOfPgReadAllData":   canRead,
			"memberOfPgWriteAllData":  canWrite,
		})
	})

	mux.HandleFunc("GET /counters", func(w http.ResponseWriter, r *http.Request) {
		pool, err := db.get(r.Context())
		if err != nil {
			dbError(w, err)
			return
		}
		rows, err := pool.Query(r.Context(), `SELECT name, value, updated_at FROM counters ORDER BY name`)
		if err != nil {
			dbError(w, err)
			return
		}
		counters, err := pgx.CollectRows(rows, pgx.RowToStructByPos[counter])
		if err != nil {
			dbError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"counters": counters})
	})

	mux.HandleFunc("GET /counters/{name}", func(w http.ResponseWriter, r *http.Request) {
		pool, err := db.get(r.Context())
		if err != nil {
			dbError(w, err)
			return
		}
		var c counter
		err = pool.QueryRow(r.Context(), `SELECT name, value, updated_at FROM counters WHERE name = $1`, r.PathValue("name")).
			Scan(&c.Name, &c.Value, &c.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "counter not found"})
			return
		}
		if err != nil {
			dbError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	})

	mux.HandleFunc("POST /counters/{name}/increment", func(w http.ResponseWriter, r *http.Request) {
		pool, err := db.get(r.Context())
		if err != nil {
			dbError(w, err)
			return
		}
		var c counter
		err = pool.QueryRow(r.Context(), `INSERT INTO counters (name, value) VALUES ($1, 1)
			ON CONFLICT (name) DO UPDATE SET value = counters.value + 1, updated_at = now()
			RETURNING name, value, updated_at`, r.PathValue("name")).
			Scan(&c.Name, &c.Value, &c.UpdatedAt)
		if err != nil {
			dbError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	})

	mux.HandleFunc("DELETE /counters/{name}", func(w http.ResponseWriter, r *http.Request) {
		pool, err := db.get(r.Context())
		if err != nil {
			dbError(w, err)
			return
		}
		tag, err := pool.Exec(r.Context(), `DELETE FROM counters WHERE name = $1`, r.PathValue("name"))
		if err != nil {
			dbError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"deleted": tag.RowsAffected()})
	})

	slog.Info("counter API starting", "port", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
