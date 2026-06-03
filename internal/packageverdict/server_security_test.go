package packageverdict

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/internal/verdictdb"
)

func newTestResolver(t *testing.T) *Resolver {
	t.Helper()
	resolver := New(verdictdb.New(filepath.Join(t.TempDir(), "scores.json")))
	resolver.httpClient = &fakeHTTPClient{}
	resolver.now = fixedClock
	return resolver
}

func verdictRequestBody() []byte {
	return []byte(`{"ecosystem":"npm","name":"left-pad","version":"1.3.0"}`)
}

func TestAuthRequiredWhenTokenSet(t *testing.T) {
	handler := HandlerWithOptions(newTestResolver(t), ServerOptions{AuthToken: "s3cret"})

	// No token -> 401.
	noToken := httptest.NewRecorder()
	handler.ServeHTTP(noToken, httptest.NewRequest(http.MethodPost, "/v0/verdict", bytes.NewReader(verdictRequestBody())))
	if noToken.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", noToken.Code)
	}

	// Wrong token -> 401.
	wrong := httptest.NewRequest(http.MethodPost, "/v0/verdict", bytes.NewReader(verdictRequestBody()))
	wrong.Header.Set("Authorization", "Bearer nope")
	wrongRec := httptest.NewRecorder()
	handler.ServeHTTP(wrongRec, wrong)
	if wrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", wrongRec.Code)
	}

	// Correct token -> 200.
	ok := httptest.NewRequest(http.MethodPost, "/v0/verdict", bytes.NewReader(verdictRequestBody()))
	ok.Header.Set("Authorization", "Bearer s3cret")
	okRec := httptest.NewRecorder()
	handler.ServeHTTP(okRec, ok)
	if okRec.Code != http.StatusOK {
		t.Fatalf("valid token status = %d body=%s, want 200", okRec.Code, okRec.Body.String())
	}
}

func TestHealthBypassesAuth(t *testing.T) {
	handler := HandlerWithOptions(newTestResolver(t), ServerOptions{AuthToken: "s3cret"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}
}

func TestRateLimitReturns429(t *testing.T) {
	limiter := newRateLimiter(60, 2)
	limiter.now = func() time.Time { return fixedClock() } // frozen clock: no refill
	handler := rateLimit(limiter, Handler(newTestResolver(t)))

	codes := make([]int, 0, 4)
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v0/verdict", bytes.NewReader(verdictRequestBody()))
		req.RemoteAddr = "203.0.113.7:5000"
		handler.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}

	// Burst of 2 allowed, then throttled.
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		t.Fatalf("first two codes = %v, want 200,200", codes[:2])
	}
	if codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Fatalf("throttled codes = %v, want 429,429", codes[2:])
	}
}

func TestRateLimitRefillsOverTime(t *testing.T) {
	now := fixedClock()
	limiter := newRateLimiter(60, 1) // 1 token/sec
	limiter.now = func() time.Time { return now }

	if !limiter.allow("k") {
		t.Fatal("first request should be allowed")
	}
	if limiter.allow("k") {
		t.Fatal("second immediate request should be throttled")
	}
	now = now.Add(2 * time.Second) // refill
	if !limiter.allow("k") {
		t.Fatal("request after refill should be allowed")
	}
}

func TestGuardExposure(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		token   string
		wantErr bool
	}{
		{"loopback no token", "127.0.0.1:8757", "", false},
		{"localhost no token", "localhost:8757", "", false},
		{"ipv6 loopback no token", "[::1]:8757", "", false},
		{"all interfaces no token", "0.0.0.0:8757", "", true},
		{"all interfaces with token", "0.0.0.0:8757", "tok", false},
		{"empty host no token", ":8757", "", true},
		{"routable no token", "10.0.0.5:8757", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := guardExposure(tc.addr, tc.token)
			if tc.wantErr && err == nil {
				t.Fatalf("guardExposure(%q, %q) = nil, want error", tc.addr, tc.token)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("guardExposure(%q, %q) = %v, want nil", tc.addr, tc.token, err)
			}
		})
	}
}
