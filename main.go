package main

import (
	"cmp"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/checkout", checkout)
	http.HandleFunc("/pinned", pinned)
	http.HandleFunc("/hang", hang)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	http.ListenAndServe(":"+cmp.Or(os.Getenv("PORT"), "8080"), nil)
}

// One request, six outbound calls.
func checkout(w http.ResponseWriter, r *http.Request) {
	call(r, "https://api.github.com/zen")           // check the user
	call(r, "https://httpbin.org/delay/1")          // load stock, slow
	call(r, "https://httpbin.org/status/503")       // charge the card, fails
	call(r, "https://httpbin.org/status/200")       // retry, works
	call(r, "https://httpbin.org/anything/receipt") // send the receipt

	// No id forwarded: shown on the Outbound page, never under this request.
	if resp, err := http.Get("https://httpbin.org/anything/analytics"); err == nil {
		resp.Body.Close()
	}
	w.Write([]byte("ok\n"))
}

// call forwards the request id, which links the call to this request.
func call(r *http.Request, url string) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Unkey-Request-Id", r.Header.Get("X-Unkey-Request-Id"))
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

// Accept the request, write no byte, and hold the connection until the gateway
// or the caller gives up. Every held request is one slot taken from frontline.
func hang(w http.ResponseWriter, r *http.Request) {
	<-r.Context().Done()
}

// A client that trusts only the system certificates, like an SDK that pins.
// The first call fails, then the proxy relays the next ones untouched.
func pinned(w http.ResponseWriter, r *http.Request) {
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	pool.AppendCertsFromPEM(pem)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	resp, err := client.Get("https://example.com")
	if err != nil {
		w.Write([]byte("failed: " + err.Error() + "\n"))
		return
	}
	resp.Body.Close()
	w.Write([]byte("ok\n"))
}
