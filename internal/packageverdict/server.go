package packageverdict

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

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

func ListenAndServe(addr string, resolver *Resolver) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = "127.0.0.1:8757"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           Handler(resolver),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}
	return server.ListenAndServe()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Fprintf(w, `{"error":"encode_failed","detail":%q}`+"\n", err.Error())
	}
}
