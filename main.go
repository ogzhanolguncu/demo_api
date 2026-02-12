package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type HelloResponse struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type DebugResponse struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Proto       string            `json:"proto"`
	Headers     map[string]string `json:"headers"`
	RawBody     string            `json:"raw_body"`
	ContentType string            `json:"content_type"`
	UserAgent   string            `json:"user_agent"`
	RemoteAddr  string            `json:"remote_addr"`
}

type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

type GreetingResponse struct {
	Greeting   string    `json:"greeting"`
	UserName   string    `json:"user_name"`
	Timestamp  time.Time `json:"timestamp"`
	APIVersion string    `json:"api_version"`
}

type Account struct {
	ID               string                 `json:"id"`
	EmailAddress     string                 `json:"email_address"`
	FullName         string                 `json:"full_name"`
	AccountType      string                 `json:"account_type"`
	Status           string                 `json:"status"`
	SubscriptionTier string                 `json:"subscription_tier"`
	CreatedTimestamp time.Time              `json:"created_timestamp"`
	LastModified     time.Time              `json:"last_modified"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type CreateAccountRequest struct {
	EmailAddress     string `json:"email_address"`
	FullName         string `json:"full_name"`
	AccountType      string `json:"account_type,omitempty"`
	SubscriptionTier string `json:"subscription_tier,omitempty"`
	PhoneNumber      string `json:"phone_number"`
	TermsAccepted    bool   `json:"terms_accepted"`
	MarketingConsent bool   `json:"marketing_consent,omitempty"`
}

type UpdateAccountRequest struct {
	EmailAddress     *string `json:"email_address,omitempty"`
	FullName         *string `json:"full_name,omitempty"`
	AccountType      *string `json:"account_type,omitempty"`
	Status           *string `json:"status,omitempty"`
	SubscriptionTier *string `json:"subscription_tier,omitempty"`
	PhoneNumber      *string `json:"phone_number,omitempty"`
	MarketingConsent *bool   `json:"marketing_consent,omitempty"`
}

type AccountListResponse struct {
	Accounts      []Account `json:"accounts"`
	NextPageToken string    `json:"next_page_token,omitempty"`
	TotalCount    int       `json:"total_count,omitempty"`
}

type PermissionsResponse struct {
	Permissions   []string `json:"permissions"`
	InheritedFrom *string  `json:"inherited_from,omitempty"`
}

type Error struct {
	Message   string    `json:"message"`
	ErrorCode string    `json:"error_code"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

type ValidationError struct {
	Message   string             `json:"message"`
	Details   []ValidationDetail `json:"details"`
	RequestID string             `json:"request_id"`
}

type ValidationDetail struct {
	Field string `json:"field"`
	Error string `json:"error"`
	Code  string `json:"code"`
}

type RootResponse struct {
	Meta      MetaInfo    `json:"meta"`
	Server    ServerInfo  `json:"server"`
	API       APIInfo     `json:"api"`
	Live      LiveMetrics `json:"live_metrics"`
	Random    RandomData  `json:"random_data"`
	Timestamp time.Time   `json:"timestamp"`
}

type MetaInfo struct {
	Service     string `json:"service"`
	Version     string `json:"version"`
	RequestID   string `json:"request_id"`
	Status      string `json:"status"`
	Environment string `json:"environment"`
}

type ServerInfo struct {
	Uptime    string    `json:"uptime"`
	StartTime time.Time `json:"start_time"`
	NodeID    string    `json:"node_id"`
	Region    string    `json:"region"`
}

type APIInfo struct {
	Endpoints map[string]EndpointMeta `json:"endpoints"`
	Versions  []string                `json:"supported_versions"`
}

type EndpointMeta struct {
	Path        string `json:"path"`
	Description string `json:"description"`
}

type LiveMetrics struct {
	Temperature  float64 `json:"simulated_temp_c"`
	StockPrice   float64 `json:"mock_stock_usd"`
	NetworkDelay float64 `json:"mock_latency_ms"`
	CPULoad      float64 `json:"simulated_cpu_percent"`
	ActiveUsers  int     `json:"mock_active_users"`
}

type RandomData struct {
	Seed        int64      `json:"entropy_seed"`
	Quote       string     `json:"wisdom"`
	Coordinates [2]float64 `json:"coordinates"`
	Hash        string     `json:"session_hash"`
}

type SystemMetrics struct {
	Memory    MemoryMetrics `json:"memory"`
	Runtime   RuntimeInfo   `json:"runtime"`
	Timestamp time.Time     `json:"timestamp"`
}

type MemoryMetrics struct {
	AllocBytes      uint64  `json:"alloc_bytes"`
	AllocMB         float64 `json:"alloc_mb"`
	TotalAllocBytes uint64  `json:"total_alloc_bytes"`
	SysBytes        uint64  `json:"sys_bytes"`
	SysMB           float64 `json:"sys_mb"`
	HeapAllocBytes  uint64  `json:"heap_alloc_bytes"`
	HeapSysBytes    uint64  `json:"heap_sys_bytes"`
}

type RuntimeInfo struct {
	NumGoroutine int    `json:"num_goroutine"`
	NumGC        uint32 `json:"num_gc"`
	GoVersion    string `json:"go_version"`
}

var (
	serverStartTime = time.Now()
	wisdomQuotes    = []string{
		"The best code is no code at all",
		"Premature optimization is the root of all evil",
		"Code is read more often than it's written",
		"Simplicity is the ultimate sophistication",
		"Make it work, make it right, make it fast",
		"Programs are meant to be read by humans and only incidentally for computers to execute",
	}
)

var (
	accountStore     = make(map[string]*Account)
	accountMutex     sync.RWMutex
	accountIDPattern = regexp.MustCompile(`^acc_[a-zA-Z0-9]{20}$`)
)

func generateAccountID() string {
	bytes := make([]byte, 10)
	_, _ = rand.Read(bytes)
	return "acc_" + hex.EncodeToString(bytes)
}

func generateRequestID() string {
	bytes := make([]byte, 8)
	_, _ = rand.Read(bytes)
	return "req_" + hex.EncodeToString(bytes)
}

func respondWithError(w http.ResponseWriter, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(Error{
		Message:   message,
		ErrorCode: errorCode,
		RequestID: generateRequestID(),
		Timestamp: time.Now().UTC(),
	})
}

func respondWithValidationError(w http.ResponseWriter, message string, details []ValidationDetail) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(ValidationError{
		Message:   message,
		Details:   details,
		RequestID: generateRequestID(),
	})
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		return nil, err
	}

	// Create a simple test table
	createTableSQL := `CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		message TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, err
	}

	slog.Info("SQLite database initialized", "file", "./test.db")
	return db, nil
}

func getSystemMetrics() SystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return SystemMetrics{
		Memory: MemoryMetrics{
			AllocBytes:      m.Alloc,
			AllocMB:         float64(m.Alloc) / 1024 / 1024,
			TotalAllocBytes: m.TotalAlloc,
			SysBytes:        m.Sys,
			SysMB:           float64(m.Sys) / 1024 / 1024,
			HeapAllocBytes:  m.HeapAlloc,
			HeapSysBytes:    m.HeapSys,
		},
		Runtime: RuntimeInfo{
			NumGoroutine: runtime.NumGoroutine(),
			NumGC:        m.NumGC,
			GoVersion:    runtime.Version(),
		},
		Timestamp: time.Now().UTC(),
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Load environment variables for testing
	rootApiKey := os.Getenv("ROOT_API_KEY")
	apiKey := os.Getenv("API_KEY")
	databaseURL := os.Getenv("DATABASE_URL")
	debugMode := os.Getenv("DEBUG_MODE")
	environment := os.Getenv("ENVIRONMENT")
	redisURL := os.Getenv("REDIS_URL")
	secretToken := os.Getenv("SECRET_TOKEN")

	slog.Info("Environment variables loaded",
		"root_api_key_set", rootApiKey != "",
		"api_key_set", apiKey != "",
		"database_url_set", databaseURL != "",
		"debug_mode", debugMode,
		"environment", environment,
		"redis_url_set", redisURL != "",
		"secret_token_set", secretToken != "",
	)

	// Initialize SQLite database
	db, err := initDB()
	if err != nil {
		slog.Error("Failed to initialize databasee", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Without this browsers automatically request /favicon.ico on every page load
		if r.URL.Path == "/favicon" {
			return
		}
		now := time.Now()
		seed := now.UnixNano()

		hashBytes := make([]byte, 6)
		_, _ = rand.Read(hashBytes)

		timeFloat := float64(now.Unix())
		temp := 22.5 + 8.0*math.Sin(timeFloat/3600.0)
		stock := 150.0 + 25.0*math.Sin(timeFloat/86400.0) + 10.0*math.Sin(timeFloat/1800.0)
		latency := 45.0 + 20.0*math.Sin(timeFloat/300.0)
		cpu := 25.0 + 15.0*math.Sin(timeFloat/600.0)
		users := int(100 + 30*math.Sin(timeFloat/900.0))

		lat := -90.0 + float64(seed%180000)/1000.0
		lng := -180.0 + float64((seed*2)%360000)/1000.0

		response := RootResponse{
			Meta: MetaInfo{
				Service:     "Demo API Server",
				Version:     "2.0.0",
				RequestID:   generateRequestID(),
				Status:      "operational",
				Environment: "development",
			},
			Server: ServerInfo{
				Uptime:    time.Since(serverStartTime).String(),
				StartTime: serverStartTime.UTC(),
				NodeID:    fmt.Sprintf("node-%x", hashBytes[:3]),
				Region:    "us-east-1",
			},
			API: APIInfo{
				Endpoints: map[string]EndpointMeta{
					"health":         {"/v2/health", "Service health check"},
					"system-metrics": {"/v2/system-metrics", "Real-time system metrics (RAM, CPU, runtime)"},
					"greeting":       {"/v2/greeting", "Personalized greeting service"},
					"accounts":       {"/v2/accounts", "Account management endpoints"},
					"debug":          {"/v1/debug", "Request debugging utility"},
					"hello":          {"/v1/hello", "Simple hello endpoint"},
					"liveness":       {"/v1/liveness", "Basic liveness check"},
					"timeout":        {"/v1/timeout", "Timeout test endpoint"},
					"protected":      {"/v1/protected", "Auth protected endpoint"},
					"openapi":        {"/openapi.yaml", "OpenAPI specification"},
				},
				Versions: []string{"v1", "v2"},
			},
			Live: LiveMetrics{
				Temperature:  math.Round(temp*10) / 10,
				StockPrice:   math.Round(stock*100) / 100,
				NetworkDelay: math.Round(latency*10) / 10,
				CPULoad:      math.Round(cpu*10) / 10,
				ActiveUsers:  users,
			},
			Random: RandomData{
				Seed:        seed,
				Quote:       wisdomQuotes[seed%int64(len(wisdomQuotes))],
				Coordinates: [2]float64{lat, lng},
				Hash:        hex.EncodeToString(hashBytes),
			},
			Timestamp: now.UTC(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", response.Meta.RequestID)
		w.Header().Set("X-Node-ID", response.Server.NodeID)
		w.WriteHeader(http.StatusOK)

		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(response)
	})

	// Health check endpoint
	mux.HandleFunc("/v1/liveness", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	})

	mux.HandleFunc("/env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, os.Environ())
	})

	// Authentication middleware for database endpoints
	// Uses SECRET_TOKEN environment variable
	if secretToken == "" {
		secretToken = "change-me-in-production"
		slog.Warn("SECRET_TOKEN not set, using default password. Set SECRET_TOKEN environment variable!")
	}

	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")

			// Support both Bearer token and Basic auth
			expectedBearer := "Bearer " + secretToken

			if auth != expectedBearer {
				w.Header().Set("WWW-Authenticate", `Bearer realm="Database Admin"`)
				http.Error(w, "Unauthorized - Invalid or missing authentication token", http.StatusUnauthorized)
				slog.Warn("Unauthorized database access attempt",
					"remote_addr", r.RemoteAddr,
					"path", r.URL.Path,
				)
				return
			}

			next(w, r)
		}
	}

	// SQLite web admin panel
	mux.HandleFunc("/v1/db-admin", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLite Database Admin</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 14px; }
        .content { padding: 30px; }
        .section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .section h2 {
            font-size: 18px;
            margin-bottom: 15px;
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        textarea, input[type="text"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px;
            resize: vertical;
            transition: border-color 0.3s;
        }
        textarea:focus, input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        button:active { transform: translateY(0); }
        .button-group { display: flex; gap: 10px; flex-wrap: wrap; }
        .results {
            background: white;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
            max-height: 500px;
            overflow: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
            position: sticky;
            top: 0;
        }
        tr:hover { background: #f8f9fa; }
        .schema-item {
            background: white;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
        }
        .schema-item h3 {
            color: #667eea;
            font-size: 16px;
            margin-bottom: 8px;
        }
        .schema-sql {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .error {
            background: #fee;
            border: 2px solid #fcc;
            color: #c33;
            padding: 12px;
            border-radius: 6px;
            margin-top: 10px;
        }
        .success {
            background: #efe;
            border: 2px solid #cfc;
            color: #363;
            padding: 12px;
            border-radius: 6px;
            margin-top: 10px;
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
        }
        .quick-queries {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }
        .quick-query {
            background: white;
            border: 2px solid #667eea;
            color: #667eea;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }
        .quick-query:hover {
            background: #667eea;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🗄️ SQLite Database Admin</h1>
            <p>View and query your remote SQLite database</p>
        </div>

        <div class="content">
            <!-- Schema Section -->
            <div class="section">
                <h2>📋 Database Schema <span class="badge" id="table-count">Loading...</span></h2>
                <button onclick="loadSchema()">🔄 Refresh Schema</button>
                <div id="schema-results" class="results">
                    <div class="loading">Loading schema...</div>
                </div>
            </div>

            <!-- Query Section -->
            <div class="section">
                <h2>🔍 Execute Query</h2>
                <div class="quick-queries">
                    <div class="quick-query" onclick="setQuery('SELECT * FROM logs ORDER BY id DESC LIMIT 10')">📝 Recent Logs</div>
                    <div class="quick-query" onclick="setQuery('SELECT COUNT(*) as total FROM logs')">🔢 Count Logs</div>
                    <div class="quick-query" onclick="setQuery('SELECT * FROM logs WHERE created_at > datetime(\'now\', \'-1 hour\')')">🕐 Last Hour</div>
                    <div class="quick-query" onclick="setQuery('SELECT * FROM sqlite_master')">🗂️ All Tables</div>
                </div>
                <textarea id="query-input" rows="4" placeholder="SELECT * FROM logs LIMIT 10">SELECT * FROM logs ORDER BY id DESC LIMIT 10</textarea>
                <button onclick="executeQuery()">▶️ Execute Query</button>
                <div id="query-results"></div>
            </div>
        </div>
    </div>

    <script>
        // Get auth token from URL parameter (e.g., ?token=your-password)
        const urlParams = new URLSearchParams(window.location.search);
        const authToken = urlParams.get('token') || '';

        if (!authToken) {
            alert('⚠️ No authentication token provided!\n\nAdd ?token=YOUR_PASSWORD to the URL\n\nExample:\n/v1/db-admin?token=your-secret-password');
        }

        function getAuthHeaders() {
            return {
                'Authorization': 'Bearer ' + authToken
            };
        }

        // Load schema on page load
        document.addEventListener('DOMContentLoaded', () => {
            loadSchema();
        });

        async function loadSchema() {
            const resultsDiv = document.getElementById('schema-results');
            resultsDiv.innerHTML = '<div class="loading">Loading schema...</div>';

            try {
                const response = await fetch('/v1/db-schema', {
                    headers: getAuthHeaders()
                });
                const data = await response.json();

                document.getElementById('table-count').textContent = data.count + ' tables';

                if (data.tables.length === 0) {
                    resultsDiv.innerHTML = '<p>No tables found in database.</p>';
                    return;
                }

                let html = '';
                data.tables.forEach(table => {
                    html += '<div class="schema-item">';
                    html += '<h3>📊 ' + table.name + '</h3>';
                    html += '<div class="schema-sql">' + table.sql + '</div>';
                    html += '</div>';
                });

                resultsDiv.innerHTML = html;
            } catch (error) {
                resultsDiv.innerHTML = '<div class="error">Error loading schema: ' + error.message + '</div>';
            }
        }

        function setQuery(query) {
            document.getElementById('query-input').value = query;
        }

        async function executeQuery() {
            const query = document.getElementById('query-input').value.trim();
            const resultsDiv = document.getElementById('query-results');

            if (!query) {
                resultsDiv.innerHTML = '<div class="error">Please enter a query</div>';
                return;
            }

            resultsDiv.innerHTML = '<div class="loading">Executing query...</div>';

            try {
                const response = await fetch('/v1/db-query', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify({ query: query })
                });

                if (!response.ok) {
                    const text = await response.text();
                    throw new Error(text);
                }

                const data = await response.json();

                if (data.count === 0) {
                    resultsDiv.innerHTML = '<div class="success">Query executed successfully. No rows returned.</div>';
                    return;
                }

                let html = '<div class="success">✅ Returned ' + data.count + ' rows</div>';
                html += '<table><thead><tr>';

                data.columns.forEach(col => {
                    html += '<th>' + col + '</th>';
                });

                html += '</tr></thead><tbody>';

                data.rows.forEach(row => {
                    html += '<tr>';
                    data.columns.forEach(col => {
                        let value = row[col];
                        if (value === null) value = '<em>NULL</em>';
                        html += '<td>' + value + '</td>';
                    });
                    html += '</tr>';
                });

                html += '</tbody></table>';
                resultsDiv.innerHTML = html;

            } catch (error) {
                resultsDiv.innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        // Allow Ctrl+Enter to execute query
        document.getElementById('query-input').addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                executeQuery();
            }
        });
    </script>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, html)
	}))

	// SQLite download endpoint - download the entire database file
	mux.HandleFunc("/v1/db-download", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Optional: Add authentication here
		// auth := r.Header.Get("Authorization")
		// if auth != "Bearer your-secret-token" {
		//     http.Error(w, "Unauthorized", http.StatusUnauthorized)
		//     return
		// }

		w.Header().Set("Content-Type", "application/x-sqlite3")
		w.Header().Set("Content-Disposition", "attachment; filename=test.db")

		http.ServeFile(w, r, "./test.db")
	}))

	// SQLite execute raw SQL endpoint (use with caution!)
	mux.HandleFunc("/v1/db-query", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Only allow SELECT queries for safety
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(req.Query)), "SELECT") {
			http.Error(w, "Only SELECT queries are allowed", http.StatusBadRequest)
			return
		}

		rows, err := db.Query(req.Query)
		if err != nil {
			slog.Error("Failed to execute query", "error", err)
			http.Error(w, fmt.Sprintf("Query error: %v", err), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		columns, err := rows.Columns()
		if err != nil {
			http.Error(w, "Failed to get columns", http.StatusInternalServerError)
			return
		}

		var results []map[string]interface{}
		for rows.Next() {
			values := make([]interface{}, len(columns))
			valuePtrs := make([]interface{}, len(columns))
			for i := range values {
				valuePtrs[i] = &values[i]
			}

			if err := rows.Scan(valuePtrs...); err != nil {
				continue
			}

			row := make(map[string]interface{})
			for i, col := range columns {
				var v interface{}
				val := values[i]
				b, ok := val.([]byte)
				if ok {
					v = string(b)
				} else {
					v = val
				}
				row[col] = v
			}
			results = append(results, row)
		}

		if results == nil {
			results = []map[string]interface{}{}
		}

		response := map[string]interface{}{
			"columns": columns,
			"rows":    results,
			"count":   len(results),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}))

	// SQLite schema endpoint - see all tables and structure
	mux.HandleFunc("/v1/db-schema", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get all tables
		rows, err := db.Query("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name")
		if err != nil {
			http.Error(w, "Failed to get schema", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var tables []map[string]interface{}
		for rows.Next() {
			var name, sql string
			if err := rows.Scan(&name, &sql); err != nil {
				continue
			}
			tables = append(tables, map[string]interface{}{
				"name": name,
				"sql":  sql,
			})
		}

		response := map[string]interface{}{
			"tables": tables,
			"count":  len(tables),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}))

	// SQLite test endpoint
	mux.HandleFunc("/v1/db-test", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// Insert a log entry
			var req struct {
				Message string `json:"message"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			result, err := db.Exec("INSERT INTO logs (message) VALUES (?)", req.Message)
			if err != nil {
				slog.Error("Failed to insert log", "error", err)
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}

			id, _ := result.LastInsertId()
			response := map[string]interface{}{
				"id":      id,
				"message": "Log entry created",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(response)

		case http.MethodGet:
			// Retrieve all logs
			rows, err := db.Query("SELECT id, message, created_at FROM logs ORDER BY id DESC LIMIT 10")
			if err != nil {
				slog.Error("Failed to query logs", "error", err)
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var logs []map[string]interface{}
			for rows.Next() {
				var id int
				var message, createdAt string
				if err := rows.Scan(&id, &message, &createdAt); err != nil {
					continue
				}
				logs = append(logs, map[string]interface{}{
					"id":         id,
					"message":    message,
					"created_at": createdAt,
				})
			}

			if logs == nil {
				logs = []map[string]interface{}{}
			}

			response := map[string]interface{}{
				"count": len(logs),
				"logs":  logs,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("Panic triggered")
	})

	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
	})

	shutdownChan := make(chan struct{})

	mux.HandleFunc("/clean-shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "Server shutting down gracefully",
			"status":  "ok",
		})

		go func() {
			time.Sleep(100 * time.Millisecond)
			close(shutdownChan)
		}()
	})

	mux.HandleFunc("/abrupt-shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Start writing response but don't finish
		_, _ = w.Write([]byte(`{"message": "Server is shutting down`))

		// Die mid-request
		os.Exit(1)
	})

	// Debug endpoint - dumps request headers and body
	mux.HandleFunc("/v1/debug", func(w http.ResponseWriter, r *http.Request) {
		// Read body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		defer func() { _ = r.Body.Close() }()

		// Convert headers to map
		headers := make(map[string]string)
		for key, values := range r.Header {
			// Join multiple values with comma
			headers[key] = strings.Join(values, ", ")
		}

		response := DebugResponse{
			Method:      r.Method,
			URL:         r.URL.String(),
			Proto:       r.Proto,
			Headers:     headers,
			RawBody:     string(bodyBytes),
			ContentType: r.Header.Get("Content-Type"),
			UserAgent:   r.Header.Get("User-Agent"),
			RemoteAddr:  r.RemoteAddr,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cookie", "123=123")
		w.Header().Set("X-Custom-Header", "CustomValue")
		w.Header().Set("X-Custom-Header", "CustomValue")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	})

	// Hello endpoint
	mux.HandleFunc("/v1/hello", func(w http.ResponseWriter, r *http.Request) {
		response := HelloResponse{
			Message:   "Hello from demo API",
			Timestamp: time.Now().UTC(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/v1/timeout", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second * 35)
	})

	mux.HandleFunc("/v1/slow", func(w http.ResponseWriter, r *http.Request) {
		// Parse sleep duration from query param (default 2s)
		duration := 2 * time.Second
		if d := r.URL.Query().Get("duration"); d != "" {
			if parsed, err := time.ParseDuration(d); err == nil {
				duration = parsed
			}
		}

		time.Sleep(duration)

		response := map[string]interface{}{
			"message":   fmt.Sprintf("Slept for %v", duration),
			"timestamp": time.Now().UTC(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/v1/log-random", func(w http.ResponseWriter, r *http.Request) {
		randomData := map[string]any{
			"request_id":  generateRequestID(),
			"temperature": 15.0 + mrand.Float64()*20.0,
			"user_count":  mrand.IntN(1000),
			"is_active":   mrand.IntN(2) == 1,
			"tags":        []string{"demo", "random", "test12"}[0 : mrand.IntN(3)+1],
			"metadata": map[string]any{
				"region":  []string{"us-east-1", "eu-west-1", "ap-south-1"}[mrand.IntN(3)],
				"version": fmt.Sprintf("v%d.%d.%d", mrand.IntN(5), mrand.IntN(10), mrand.IntN(20)),
			},
		}

		slog.Info("random data logged",
			"request_id", randomData["request_id"],
			"temperature", randomData["temperature"],
			"user_count", randomData["user_count"],
			"is_active", randomData["is_active"],
			"tags", randomData["tags"],
			"metadata", randomData["metadata"],
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "random data logged to console",
			"data":    randomData,
		})
	})

	mux.HandleFunc("/v1/protected", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if auth == "" || auth != "Bearer 123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})

	// V2 API Endpoints
	// Health endpoint
	mux.HandleFunc("/v2/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			return
		}

		response := HealthResponse{
			Status:    "healthy",
			Timestamp: time.Now().UTC(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	})

	// System metrics endpoint
	mux.HandleFunc("/v2/system-metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			return
		}

		metrics := getSystemMetrics()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(metrics)
	})

	// Greeting endpoint
	mux.HandleFunc("/v2/greeting", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			return
		}

		name := r.URL.Query().Get("name")
		if name == "" {
			respondWithError(w, http.StatusBadRequest, "MISSING_PARAMETER", "Missing or invalid name parameter")
			return
		}

		response := GreetingResponse{
			Greeting:   fmt.Sprintf("Hello, %s!", name),
			UserName:   name,
			Timestamp:  time.Now().UTC(),
			APIVersion: "2.0.0",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	})

	// Accounts endpoints
	mux.HandleFunc("/v2/accounts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Get all accounts
			pageSize := 20
			if ps := r.URL.Query().Get("page_size"); ps != "" {
				if size, err := strconv.Atoi(ps); err == nil && size >= 1 && size <= 50 {
					pageSize = size
				}
			}

			pageToken := r.URL.Query().Get("page_token")
			status := r.URL.Query().Get("status")

			accountMutex.RLock()
			accounts := make([]Account, 0)
			for _, acc := range accountStore {
				if status != "" && acc.Status != status {
					continue
				}
				accounts = append(accounts, *acc)
			}
			accountMutex.RUnlock()

			// Simple pagination - in production would use proper cursor
			start := 0
			if pageToken != "" {
				if idx, err := strconv.Atoi(pageToken); err == nil {
					start = idx
				}
			}

			end := start + pageSize
			if end > len(accounts) {
				end = len(accounts)
			}

			var nextPageToken string
			if end < len(accounts) {
				nextPageToken = strconv.Itoa(end)
			}

			response := AccountListResponse{
				Accounts:      accounts[start:end],
				NextPageToken: nextPageToken,
				TotalCount:    len(accounts),
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)

		case http.MethodPost:
			// Create account
			var req CreateAccountRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondWithError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
				return
			}

			// Validate required fields
			var validationErrors []ValidationDetail

			if req.EmailAddress == "" || !strings.Contains(req.EmailAddress, "@") {
				validationErrors = append(validationErrors, ValidationDetail{
					Field: "email_address",
					Error: "Must be a valid email address",
					Code:  "INVALID_EMAIL",
				})
			}

			if req.FullName == "" || len(req.FullName) < 2 || len(req.FullName) > 100 {
				validationErrors = append(validationErrors, ValidationDetail{
					Field: "full_name",
					Error: "Must be between 2 and 100 characters",
					Code:  "INVALID_NAME",
				})
			}

			if req.PhoneNumber == "" || !strings.HasPrefix(req.PhoneNumber, "+") {
				validationErrors = append(validationErrors, ValidationDetail{
					Field: "phone_number",
					Error: "Must be a valid phone number with country code",
					Code:  "INVALID_PHONE",
				})
			}

			if !req.TermsAccepted {
				validationErrors = append(validationErrors, ValidationDetail{
					Field: "terms_accepted",
					Error: "Terms must be accepted",
					Code:  "TERMS_NOT_ACCEPTED",
				})
			}

			if len(validationErrors) > 0 {
				respondWithValidationError(w, "Validation failed", validationErrors)
				return
			}

			// Check for duplicate email
			accountMutex.RLock()
			for _, acc := range accountStore {
				if acc.EmailAddress == req.EmailAddress {
					accountMutex.RUnlock()
					respondWithError(w, http.StatusConflict, "ACCOUNT_EXISTS", "Account already exists")
					return
				}
			}
			accountMutex.RUnlock()

			// Set defaults
			if req.AccountType == "" {
				req.AccountType = "standard"
			}
			if req.SubscriptionTier == "" {
				req.SubscriptionTier = "free"
			}

			// Create account
			account := &Account{
				ID:               generateAccountID(),
				EmailAddress:     req.EmailAddress,
				FullName:         req.FullName,
				AccountType:      req.AccountType,
				Status:           "active",
				SubscriptionTier: req.SubscriptionTier,
				CreatedTimestamp: time.Now().UTC(),
				LastModified:     time.Now().UTC(),
				Metadata: map[string]interface{}{
					"source":            "api",
					"marketing_consent": req.MarketingConsent,
					"phone_number":      req.PhoneNumber,
				},
			}

			accountMutex.Lock()
			accountStore[account.ID] = account
			accountMutex.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(account)

		default:
			respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
	})

	// Account by ID endpoints
	mux.HandleFunc("/v2/accounts/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
		parts := strings.Split(path, "/")

		if len(parts) == 0 || parts[0] == "" {
			respondWithError(w, http.StatusNotFound, "NOT_FOUND", "Not found")
			return
		}

		accountID := parts[0]

		// Validate account ID format
		if !accountIDPattern.MatchString(accountID) {
			respondWithError(w, http.StatusBadRequest, "INVALID_ACCOUNT_ID", "Invalid account ID format")
			return
		}

		// Handle permissions endpoint
		if len(parts) > 1 && parts[1] == "permissions" {
			if r.Method != http.MethodGet {
				respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
				return
			}

			accountMutex.RLock()
			account, exists := accountStore[accountID]
			accountMutex.RUnlock()

			if !exists {
				respondWithError(w, http.StatusNotFound, "ACCOUNT_NOT_FOUND", "Account not found")
				return
			}

			// Mock permissions based on account type
			var permissions []string
			var inheritedFrom *string

			switch account.AccountType {
			case "premium":
				permissions = []string{"read", "write", "delete", "admin", "billing"}
				roleType := "premium_role"
				inheritedFrom = &roleType
			case "standard":
				permissions = []string{"read", "write"}
				roleType := "standard_role"
				inheritedFrom = &roleType
			case "basic":
				permissions = []string{"read"}
				roleType := "basic_role"
				inheritedFrom = &roleType
			}

			response := PermissionsResponse{
				Permissions:   permissions,
				InheritedFrom: inheritedFrom,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		// Handle account CRUD operations
		switch r.Method {
		case http.MethodGet:
			accountMutex.RLock()
			account, exists := accountStore[accountID]
			accountMutex.RUnlock()

			if !exists {
				respondWithError(w, http.StatusNotFound, "ACCOUNT_NOT_FOUND", "Account not found")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(account)

		case http.MethodPatch:
			var req UpdateAccountRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondWithError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
				return
			}

			accountMutex.Lock()
			account, exists := accountStore[accountID]
			if !exists {
				accountMutex.Unlock()
				respondWithError(w, http.StatusNotFound, "ACCOUNT_NOT_FOUND", "Account not found")
				return
			}

			// Validate and apply updates
			var validationErrors []ValidationDetail

			if req.EmailAddress != nil {
				if !strings.Contains(*req.EmailAddress, "@") {
					validationErrors = append(validationErrors, ValidationDetail{
						Field: "email_address",
						Error: "Must be a valid email address",
						Code:  "INVALID_EMAIL",
					})
				} else {
					account.EmailAddress = *req.EmailAddress
				}
			}

			if req.FullName != nil {
				if len(*req.FullName) < 2 || len(*req.FullName) > 100 {
					validationErrors = append(validationErrors, ValidationDetail{
						Field: "full_name",
						Error: "Must be between 2 and 100 characters",
						Code:  "INVALID_NAME",
					})
				} else {
					account.FullName = *req.FullName
				}
			}

			if req.Status != nil && (*req.Status == "pending") {
				validationErrors = append(validationErrors, ValidationDetail{
					Field: "status",
					Error: "Cannot set status to pending",
					Code:  "INVALID_STATUS",
				})
			}

			if len(validationErrors) > 0 {
				accountMutex.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				_ = json.NewEncoder(w).Encode(ValidationError{
					Message:   "Invalid update data",
					Details:   validationErrors,
					RequestID: generateRequestID(),
				})
				return
			}

			// Apply other updates
			if req.AccountType != nil {
				account.AccountType = *req.AccountType
			}
			if req.Status != nil {
				account.Status = *req.Status
			}
			if req.SubscriptionTier != nil {
				account.SubscriptionTier = *req.SubscriptionTier
			}
			if req.PhoneNumber != nil {
				if account.Metadata == nil {
					account.Metadata = make(map[string]interface{})
				}
				account.Metadata["phone_number"] = *req.PhoneNumber
			}
			if req.MarketingConsent != nil {
				if account.Metadata == nil {
					account.Metadata = make(map[string]interface{})
				}
				account.Metadata["marketing_consent"] = *req.MarketingConsent
			}

			account.LastModified = time.Now().UTC()
			accountMutex.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(account)

		case http.MethodDelete:
			accountMutex.Lock()
			_, exists := accountStore[accountID]
			if !exists {
				accountMutex.Unlock()
				respondWithError(w, http.StatusNotFound, "ACCOUNT_NOT_FOUND", "Account not found")
				return
			}

			delete(accountStore, accountID)
			accountMutex.Unlock()

			w.WriteHeader(http.StatusNoContent)

		default:
			respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
	})

	// OpenAPI spec endpoint - VERSION 2 (Breaking Changes)
	mux.HandleFunc("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		spec := `openapi: 3.1.0
info:
  title: Demo API
  description: A simple demo API for testing deployments with breaking changes
  version: 2.0.0
  contact:
    name: Unkey Support
    email: support@unkey.dev
servers:
  - url: /v2
    description: API v2 (BREAKING CHANGES)
paths:
  /health:
    get:
      operationId: getHealth
      summary: Health check endpoint (renamed from liveness)
      description: Returns OK if the service is healthy
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: "healthy"
                  timestamp:
                    type: string
                    format: date-time
                required:
                  - status
                  - timestamp
  /greeting:
    get:
      operationId: getGreeting
      summary: Greeting endpoint (renamed from hello)
      description: Returns a greeting message with timestamp
      parameters:
        - name: name
          in: query
          description: Name to greet (new required parameter)
          required: true
          schema:
            type: string
            minLength: 3
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/GreetingResponse'
        '400':
          description: Missing or invalid name parameter
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
  /accounts:
    get:
      operationId: getAccounts
      summary: Get all accounts (renamed from users)
      description: Returns a list of user accounts
      parameters:
        - name: page_size
          in: query
          description: Number of accounts per page (renamed from limit)
          required: false
          schema:
            type: integer
            minimum: 1
            maximum: 50
            default: 20
        - name: page_token
          in: query
          description: Pagination token (changed from offset)
          required: false
          schema:
            type: string
        - name: status
          in: query
          description: Filter by account status (new parameter)
          required: false
          schema:
            type: string
            enum: [active, suspended, pending]
      responses:
        '200':
          description: List of accounts
          content:
            application/json:
              schema:
                type: object
                properties:
                  accounts:
                    type: array
                    items:
                      $ref: '#/components/schemas/Account'
                  next_page_token:
                    type: string
                    description: Token for next page
                  total_count:
                    type: integer
                    description: Total number of accounts
                required:
                  - accounts
    post:
      operationId: createAccount
      summary: Create a new account
      description: Creates a new user account with enhanced validation
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateAccountRequest'
      responses:
        '201':
          description: Account created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Account'
        '400':
          description: Invalid request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ValidationError'
        '409':
          description: Account already exists
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
  /accounts/{accountId}:
    get:
      operationId: getAccountById
      summary: Get account by ID
      description: Returns a specific account by their ID
      parameters:
        - name: accountId
          in: path
          required: true
          description: The account ID (changed pattern)
          schema:
            type: string
            pattern: '^acc_[a-zA-Z0-9]{20}$'
      responses:
        '200':
          description: Account found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Account'
        '404':
          description: Account not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    patch:
      operationId: updateAccount
      summary: Update account (changed from PUT to PATCH)
      description: Partially updates an existing account
      parameters:
        - name: accountId
          in: path
          required: true
          description: The account ID
          schema:
            type: string
            pattern: '^acc_[a-zA-Z0-9]{20}$'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateAccountRequest'
      responses:
        '200':
          description: Account updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Account'
        '404':
          description: Account not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '422':
          description: Invalid update data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ValidationError'
    delete:
      operationId: deleteAccount
      summary: Delete account (new endpoint)
      description: Permanently deletes an account
      parameters:
        - name: accountId
          in: path
          required: true
          description: The account ID
          schema:
            type: string
            pattern: '^acc_[a-zA-Z0-9]{20}$'
      responses:
        '204':
          description: Account deleted successfully
        '404':
          description: Account not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
  /accounts/{accountId}/permissions:
    get:
      operationId: getAccountPermissions
      summary: Get account permissions (new endpoint)
      description: Returns permissions for a specific account
      parameters:
        - name: accountId
          in: path
          required: true
          description: The account ID
          schema:
            type: string
            pattern: '^acc_[a-zA-Z0-9]{20}$'
      responses:
        '200':
          description: Account permissions
          content:
            application/json:
              schema:
                type: object
                properties:
                  permissions:
                    type: array
                    items:
                      type: string
                  inherited_from:
                    type: [string, null]
                required:
                  - permissions
components:
  schemas:
    GreetingResponse:
      type: object
      properties:
        greeting:
          type: string
          description: The personalized greeting message
          example: "Hello, John!"
        user_name:
          type: string
          description: The name that was greeted
          example: "John"
        timestamp:
          type: string
          format: date-time
          description: The current timestamp
          example: "2023-12-07T10:30:00Z"
        api_version:
          type: string
          description: API version used
          example: "2.0.0"
      required:
        - greeting
        - user_name
        - timestamp
        - api_version
    Account:
      type: object
      properties:
        id:
          type: string
          description: Unique account identifier (changed pattern)
          pattern: '^acc_[a-zA-Z0-9]{20}$'
          example: "acc_1234567890abcdef1234"
        email_address:
          type: string
          format: email
          description: Account email address (renamed field)
          example: "john.doe@example.com"
        full_name:
          type: string
          description: Account holder's full name (renamed field)
          example: "John Doe"
        account_type:
          type: string
          enum: [premium, standard, basic]
          description: Account type (changed from role)
          example: "standard"
        status:
          type: string
          enum: [active, suspended, pending]
          description: Account status (new field)
          example: "active"
        subscription_tier:
          type: string
          enum: [free, pro, enterprise]
          description: Subscription tier (new field)
          example: "pro"
        created_timestamp:
          type: string
          format: date-time
          description: When the account was created (renamed field)
          example: "2023-12-07T10:30:00Z"
        last_modified:
          type: string
          format: date-time
          description: When the account was last modified (renamed field)
          example: "2023-12-07T10:30:00Z"
        metadata:
          type: object
          description: Additional account metadata (new field)
          additionalProperties: true
          example: {"source": "web", "referrer": "google"}
      required:
        - id
        - email_address
        - full_name
        - account_type
        - status
        - subscription_tier
        - created_timestamp
        - last_modified
    CreateAccountRequest:
      type: object
      properties:
        email_address:
          type: string
          format: email
          description: Account email address
          example: "john.doe@example.com"
        full_name:
          type: string
          description: Account holder's full name
          minLength: 2
          maxLength: 100
          example: "John Doe"
        account_type:
          type: string
          enum: [premium, standard, basic]
          description: Account type
          default: "standard"
          example: "standard"
        subscription_tier:
          type: string
          enum: [free, pro, enterprise]
          description: Subscription tier
          default: "free"
          example: "free"
        phone_number:
          type: string
          description: Phone number (new required field)
          pattern: '^\+[1-9]\d{1,14}$'
          example: "+1234567890"
        terms_accepted:
          type: boolean
          description: Whether terms of service were accepted (new required field)
          example: true
        marketing_consent:
          type: boolean
          description: Marketing consent flag (new field)
          default: false
          example: false
      required:
        - email_address
        - full_name
        - phone_number
        - terms_accepted
    UpdateAccountRequest:
      type: object
      properties:
        email_address:
          type: string
          format: email
          description: Account email address
          example: "john.doe@example.com"
        full_name:
          type: string
          description: Account holder's full name
          minLength: 2
          maxLength: 100
          example: "John Doe"
        account_type:
          type: string
          enum: [premium, standard, basic]
          description: Account type
          example: "premium"
        status:
          type: string
          enum: [active, suspended]
          description: Account status (pending cannot be set via update)
          example: "active"
        subscription_tier:
          type: string
          enum: [free, pro, enterprise]
          description: Subscription tier
          example: "pro"
        phone_number:
          type: string
          description: Phone number
          pattern: '^\+[1-9]\d{1,14}$'
          example: "+1234567890"
        marketing_consent:
          type: boolean
          description: Marketing consent flag
          example: true
    ValidationError:
      type: object
      properties:
        message:
          type: string
          description: Main error message
          example: "Validation failed"
        details:
          type: array
          items:
            type: object
            properties:
              field:
                type: string
                description: Field that failed validation
                example: "email_address"
              error:
                type: string
                description: Specific validation error
                example: "Must be a valid email address"
              code:
                type: string
                description: Error code
                example: "INVALID_EMAIL"
            required:
              - field
              - error
              - code
        request_id:
          type: string
          description: Request ID for tracking
          example: "req_1234567890abcdef"
      required:
        - message
        - details
        - request_id
    Error:
      type: object
      properties:
        message:
          type: string
          description: Error message (renamed from error)
          example: "Account not found"
        error_code:
          type: string
          description: Error code (renamed from code)
          example: "ACCOUNT_NOT_FOUND"
        request_id:
          type: string
          description: Request ID for tracking (new field)
          example: "req_1234567890abcdef"
        timestamp:
          type: string
          format: date-time
          description: When the error occurred (new field)
          example: "2023-12-07T10:30:00Z"
      required:
        - message
        - error_code
        - request_id
        - timestamp`

		w.Header().Set("Content-Type", "application/yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, spec)
	})

	slog.Info("Demo API starting", "port", port)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	<-shutdownChan
	slog.Info("Shutdown signal received, shutting down gracefully")
	if err := server.Close(); err != nil {
		slog.Error("Error during shutdown", "error", err)
	}
	slog.Info("Server stopped")
}
