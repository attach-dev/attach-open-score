package packageverdict

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// visitorTTL bounds how long an idle client is tracked before its bucket is
// reclaimed. It keeps the limiter's memory bounded even under a flood of
// distinct source addresses.
const visitorTTL = 10 * time.Minute

// rateLimiter is a dependency-free per-client token bucket. When the service is
// fronted by a reverse proxy every request shares the proxy's address, so the
// limiter degrades to a single global bucket — an intentional backstop that
// still caps total throughput if the edge limiter is ever bypassed.
type rateLimiter struct {
	mu        sync.Mutex
	visitors  map[string]*visitor
	rate      float64 // tokens refilled per second
	burst     float64 // maximum bucket size
	now       func() time.Time
	lastSweep time.Time
}

type visitor struct {
	tokens   float64
	lastSeen time.Time
}

// newRateLimiter builds a limiter allowing requestsPerMinute sustained requests
// with the given burst. A burst < 1 falls back to one minute of requests.
func newRateLimiter(requestsPerMinute, burst int) *rateLimiter {
	if requestsPerMinute < 1 {
		requestsPerMinute = 1
	}
	if burst < 1 {
		burst = requestsPerMinute
	}
	return &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     float64(requestsPerMinute) / 60.0,
		burst:    float64(burst),
		now:      time.Now,
	}
}

// allow reports whether a request from key may proceed, consuming a token.
func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweepLocked(now)

	v, ok := l.visitors[key]
	if !ok {
		v = &visitor{tokens: l.burst, lastSeen: now}
		l.visitors[key] = v
	} else {
		elapsed := now.Sub(v.lastSeen).Seconds()
		if elapsed > 0 {
			v.tokens += elapsed * l.rate
			if v.tokens > l.burst {
				v.tokens = l.burst
			}
		}
		v.lastSeen = now
	}

	if v.tokens < 1 {
		return false
	}
	v.tokens--
	return true
}

// sweepLocked evicts visitors idle longer than visitorTTL. It runs at most once
// per TTL window so the common path stays O(1). Caller must hold l.mu.
func (l *rateLimiter) sweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < visitorTTL {
		return
	}
	l.lastSweep = now
	for k, v := range l.visitors {
		if now.Sub(v.lastSeen) > visitorTTL {
			delete(l.visitors, k)
		}
	}
}

// clientKey derives the rate-limit bucket key from the request's source
// address. We deliberately do not trust X-Forwarded-For here: a trusted edge
// proxy enforces per-real-client limits, and honoring a spoofable header would
// let a caller mint unlimited buckets.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimit wraps next, rejecting requests that exceed the limiter with 429.
func rateLimit(l *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientKey(r)) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
