package packageverdict

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ServerOptions configures the network-facing behavior of the verdict service.
// The zero value is safe for a loopback-only, single-process deployment.
type ServerOptions struct {
	// AuthToken, when non-empty, requires callers to present
	// "Authorization: Bearer <token>" on every endpoint except /health.
	AuthToken string
	// RequestsPerMinute enables per-client rate limiting when > 0.
	RequestsPerMinute int
	// Burst is the rate limiter's bucket size; defaults to RequestsPerMinute.
	Burst int
	// ReadTimeout/WriteTimeout/IdleTimeout bound slow or idle connections.
	// Zero values fall back to conservative defaults.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type VerdictRequest struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	PolicyProfile string `json:"policy_profile,omitempty"`
}

func Handler(resolver *Resolver) http.Handler {
	if resolver == nil {
		resolver = New(nil)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/v0/verdict", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		var input VerdictRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "detail": err.Error()})
			return
		}
		verdict, cached, err := resolver.Resolve(r.Context(), Request{
			Ecosystem:     input.Ecosystem,
			Name:          input.Name,
			Version:       input.Version,
			PolicyProfile: input.PolicyProfile,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "verdict_failed", "detail": err.Error()})
			return
		}
		w.Header().Set("X-Attach-Open-Score-Cache", cacheHeader(cached))
		writeJSON(w, http.StatusOK, verdict)
	})
	return mux
}

func cacheHeader(cached bool) string {
	if cached {
		return "hit"
	}
	return "miss"
}

// HandlerWithOptions returns the verdict handler wrapped with the auth and
// rate-limiting middleware implied by opts. With a zero ServerOptions it is
// equivalent to Handler.
func HandlerWithOptions(resolver *Resolver, opts ServerOptions) http.Handler {
	h := Handler(resolver)
	if token := strings.TrimSpace(opts.AuthToken); token != "" {
		h = requireBearer(token, h)
	}
	if opts.RequestsPerMinute > 0 {
		h = rateLimit(newRateLimiter(opts.RequestsPerMinute, opts.Burst), h)
	}
	return h
}

// requireBearer enforces a constant-time Bearer-token check on every path
// except /health, which stays open for liveness probes.
func requireBearer(token string, next http.Handler) http.Handler {
	expected := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		got := bearerToken(r.Header.Get("Authorization"))
		if got == "" || subtle.ConstantTimeCompare([]byte(got), expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	header = strings.TrimSpace(header)
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func ListenAndServe(addr string, resolver *Resolver) error {
	return ListenAndServeWithOptions(addr, resolver, ServerOptions{})
}

// ListenAndServeWithOptions starts the verdict service on addr. It refuses to
// bind a non-loopback address unless an auth token is configured, so the
// service can never be exposed to a network unauthenticated by accident.
func ListenAndServeWithOptions(addr string, resolver *Resolver, opts ServerOptions) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = "127.0.0.1:8757"
	}
	if err := guardExposure(addr, opts.AuthToken); err != nil {
		return err
	}

	readTimeout := opts.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 15 * time.Second
	}
	writeTimeout := opts.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 30 * time.Second
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           HandlerWithOptions(resolver, opts),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	return server.ListenAndServe()
}

// guardExposure blocks binding a routable address without authentication.
func guardExposure(addr, token string) error {
	if strings.TrimSpace(token) != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("refusing to serve on non-loopback address %q without authentication; set an auth token (ATTACH_OPEN_SCORE_API_TOKEN / --auth-token) or bind 127.0.0.1", addr)
}

// isLoopbackHost reports whether host is a loopback bind. An empty host means
// "all interfaces" and is treated as non-loopback.
func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Fprintf(w, `{"error":"encode_failed","detail":%q}`+"\n", err.Error())
	}
}
