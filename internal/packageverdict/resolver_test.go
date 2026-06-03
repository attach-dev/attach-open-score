package packageverdict

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/internal/verdictdb"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

type fakeHTTPClient struct {
	calls int
	body  string
	err   error
}

func (c *fakeHTTPClient) Do(*http.Request) (*http.Response, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	body := c.body
	if body == "" {
		body = `{"vulns":[]}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func TestResolverCachesPackageVerdicts(t *testing.T) {
	client := &fakeHTTPClient{}
	resolver := New(verdictdb.New(filepath.Join(t.TempDir(), "scores.json")))
	resolver.httpClient = client
	resolver.now = fixedClock

	request := Request{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}

	first, cached, err := resolver.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if cached {
		t.Fatal("first verdict unexpectedly came from cache")
	}
	if first.Decision != schema.DecisionAllow {
		t.Fatalf("first decision = %s, want ALLOW", first.Decision)
	}

	second, cached, err := resolver.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !cached {
		t.Fatal("second verdict did not come from cache")
	}
	if client.calls != 1 {
		t.Fatalf("OSV calls = %d, want 1", client.calls)
	}
	if second.EvaluatedAt != first.EvaluatedAt {
		t.Fatalf("cached verdict evaluated_at = %q, want original %q", second.EvaluatedAt, first.EvaluatedAt)
	}
}

func TestHandlerReturnsCacheHeader(t *testing.T) {
	client := &fakeHTTPClient{}
	resolver := New(verdictdb.New(filepath.Join(t.TempDir(), "scores.json")))
	resolver.httpClient = client
	resolver.now = fixedClock
	handler := Handler(resolver)
	body := []byte(`{"ecosystem":"npm","name":"left-pad","version":"1.3.0"}`)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/v0/verdict", bytes.NewReader(body)))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d body=%s", first.Code, first.Body.String())
	}
	if got := first.Header().Get("X-Attach-Open-Score-Cache"); got != "miss" {
		t.Fatalf("first cache header = %q, want miss", got)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/v0/verdict", bytes.NewReader(body)))
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d body=%s", second.Code, second.Body.String())
	}
	if got := second.Header().Get("X-Attach-Open-Score-Cache"); got != "hit" {
		t.Fatalf("second cache header = %q, want hit", got)
	}
}

func fixedClock() time.Time {
	return time.Date(2026, 6, 3, 9, 30, 0, 0, time.UTC)
}
