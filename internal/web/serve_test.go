package web

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/demo"
	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/store"
)

// TestServeDemo is not a test. It puts the dashboard with the demo homelab into a real browser,
// for whoever changes a template or the stylesheet:
//
//	UPKEEP_WEB_SERVE=127.0.0.1:8377 go test ./internal/web -run TestServeDemo
//
// It serves for UPKEEP_WEB_SERVE_FOR (default 2m) and then stops by itself, so nothing is left
// running. "?theme=dark" or "?theme=light" on any page forces that theme, which a headless
// browser taking screenshots cannot do through the switch. UPKEEP_WEB_SERVE_REAL=1 uses
// model.Findings instead of the hand-written findings of the tests. UPKEEP_WEB_SERVE_HOSTILE=1
// serves the store of TestEscaping instead of the demo, to see in a browser that nothing runs.
func TestServeDemo(t *testing.T) {
	addr := os.Getenv("UPKEEP_WEB_SERVE")
	if addr == "" {
		t.Skip("set UPKEEP_WEB_SERVE=127.0.0.1:8377 to look at the dashboard in a browser")
	}
	host, _, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		t.Fatalf("UPKEEP_WEB_SERVE=%q: the demo is served on a loopback address only", addr)
	}
	lifetime := 2 * time.Minute
	if v := os.Getenv("UPKEEP_WEB_SERVE_FOR"); v != "" {
		if lifetime, err = time.ParseDuration(v); err != nil {
			t.Fatalf("UPKEEP_WEB_SERVE_FOR: %v", err)
		}
	}

	s := store.NewMemory()
	if err := demo.Fill(context.Background(), s, time.Now()); err != nil {
		t.Fatal(err)
	}
	opts := Options{Store: s, Policy: model.DefaultPolicy(), Version: "demo", findings: demoFindings}
	if os.Getenv("UPKEEP_WEB_SERVE_REAL") != "" {
		opts.findings = nil
	}
	if os.Getenv("UPKEEP_WEB_SERVE_HOSTILE") != "" {
		hs, findings := hostileStore(t)
		opts.Store = hs
		opts.Now = func() time.Time { return testNow }
		opts.findings = func([]model.SystemState, map[string]model.ImageCheck, time.Time, model.Policy) []model.Finding {
			return findings
		}
	}
	srv := &http.Server{Addr: addr, Handler: forceTheme(Handler(opts)), ReadHeaderTimeout: 5 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	defer cancel()
	go func() {
		<-ctx.Done()
		stop, cancelStop := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelStop()
		srv.Shutdown(stop)
	}()
	t.Logf("serving the demo on http://%s/ for %s", addr, lifetime)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve the demo on %s: %v", addr, err)
	}
}

// forceTheme writes the theme named in the query into the page, the same way the switch does.
func forceTheme(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		theme := r.URL.Query().Get("theme")
		if theme != "dark" && theme != "light" {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(bytes.Replace(rec.Body.Bytes(), []byte(`<html lang="en">`), []byte(`<html lang="en" data-theme="`+theme+`">`), 1))
	})
}
