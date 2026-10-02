package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// registerOutbound adds endpoints that make outbound HTTPS calls so the
// egress proxy has something to observe.
//
//	GET /v1/outbound?url=https://api.github.com/&n=3         default client, trusts SSL_CERT_FILE
//	GET /v1/outbound/pinned?url=https://api.github.com/      ignores SSL_CERT_FILE, rejects the proxy CA
func registerOutbound(mux *http.ServeMux) {
	pinnedPool := x509.NewCertPool()
	if pem, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt"); err == nil {
		pinnedPool.AppendCertsFromPEM(pem)
	}
	pinned := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pinnedPool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}

	mux.HandleFunc("/v1/outbound", func(w http.ResponseWriter, r *http.Request) { outbound(w, r, http.DefaultClient) })
	mux.HandleFunc("/v1/outbound/pinned", func(w http.ResponseWriter, r *http.Request) { outbound(w, r, pinned) })
}

type outboundResult struct {
	Status int     `json:"status,omitempty"`
	Bytes  int64   `json:"bytes,omitempty"`
	Proto  string  `json:"proto,omitempty"`
	AppMs  float64 `json:"app_ms"`
	Error  string  `json:"error,omitempty"`
}

func outbound(w http.ResponseWriter, r *http.Request, client *http.Client) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "https://api.github.com/"
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	n = max(1, min(n, 50))

	results := make([]outboundResult, 0, n)
	for range n {
		started := time.Now()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		if err != nil {
			results = append(results, outboundResult{Error: err.Error(), AppMs: msSince(started)})
			continue
		}
		if id := r.Header.Get("X-Unkey-Request-Id"); id != "" {
			req.Header.Set("X-Unkey-Request-Id", id)
		}
		resp, err := client.Do(req)
		if err != nil {
			results = append(results, outboundResult{Error: err.Error(), AppMs: msSince(started)})
			continue
		}
		bytes, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		results = append(results, outboundResult{Status: resp.StatusCode, Bytes: bytes, Proto: resp.Proto, AppMs: msSince(started)})
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"target":        target,
		"ssl_cert_file": os.Getenv("SSL_CERT_FILE"),
		"results":       results,
	})
}

func msSince(started time.Time) float64 {
	return float64(time.Since(started).Microseconds()) / 1000
}
