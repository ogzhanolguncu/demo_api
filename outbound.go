package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
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
	mux.HandleFunc("/v1/checkout", checkout)
	mux.HandleFunc("/v1/order", order)
}

// checkout makes the three kinds of outbound call a real handler makes:
//
//	linked     forwards the request ids, so the call links to this request
//	unlinked   a plain client call, shown only as an estimated call
//	background starts after the response, outside the request window
func checkout(w http.ResponseWriter, r *http.Request) {
	linked := callOutbound(r.Context(), http.MethodGet, "https://api.github.com/zen", r.Header)
	unlinked := callOutbound(r.Context(), http.MethodGet, "https://httpbin.org/get", nil)

	go func() {
		time.Sleep(2 * time.Second)
		_ = callOutbound(context.Background(), http.MethodGet, "https://httpbin.org/delay/1", nil)
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]outboundResult{"linked": linked, "unlinked": unlinked})
}

// order is a fully traced handler: every call forwards the request ids, so
// every call links to the request. It runs the shapes a real handler has:
//
//  1. auth check            sequential
//  2. inventory, pricing,   parallel fan-out, one slow dependency
//     recommendations
//  3. payment               fails with 503, then a retry succeeds
//  4. write the order       sequential
func order(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	results := map[string]outboundResult{}
	var mu sync.Mutex
	record := func(name string, result outboundResult) {
		mu.Lock()
		results[name] = result
		mu.Unlock()
	}

	record("auth", callOutbound(ctx, http.MethodGet, "https://api.github.com/zen", r.Header))

	var wg sync.WaitGroup
	for name, target := range map[string]string{
		"inventory":       "https://httpbin.org/get",
		"pricing":         "https://httpbin.org/uuid",
		"recommendations": "https://httpbin.org/delay/1",
	} {
		wg.Go(func() { record(name, callOutbound(ctx, http.MethodGet, target, r.Header)) })
	}
	wg.Wait()

	record("payment", callOutbound(ctx, http.MethodGet, "https://httpbin.org/status/503", r.Header))
	record("payment_retry", callOutbound(ctx, http.MethodGet, "https://httpbin.org/status/200", r.Header))
	record("write", callOutbound(ctx, http.MethodPost, "https://httpbin.org/post", r.Header))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func callOutbound(ctx context.Context, method, target string, forward http.Header) outboundResult {
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return outboundResult{Error: err.Error(), AppMs: msSince(started)}
	}
	for _, name := range []string{"X-Unkey-Request-Id", "Traceparent"} {
		if v := forward.Get(name); v != "" {
			req.Header.Set(name, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return outboundResult{Error: err.Error(), AppMs: msSince(started)}
	}
	bytes, _ := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return outboundResult{Status: resp.StatusCode, Bytes: bytes, Proto: resp.Proto, AppMs: msSince(started)}
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
