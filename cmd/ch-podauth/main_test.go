//go:build unix

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rorylshanks/ch-podauth/internal/auth"
	"github.com/rorylshanks/ch-podauth/internal/config"
	"github.com/rorylshanks/ch-podauth/internal/metrics"
	"github.com/rorylshanks/ch-podauth/internal/token"
)

func TestReloadMappingsPicksUpConfigChanges(t *testing.T) {
	path := writeConfig(t, "reader")
	cfg, authService := startFromConfig(t, path)

	writeConfigAt(t, path, "writer")
	next, err := reloadMappings(path, cfg, authService, metrics.New(), discardLogger())
	if err != nil {
		t.Fatalf("reloadMappings() = %v", err)
	}

	if !authService.Allowed(testIdentity, "writer") {
		t.Error("writer not authorized after reload")
	}
	if authService.Allowed(testIdentity, "reader") {
		t.Error("reader still authorized after being dropped from the config")
	}
	if got := next.Mappings[0].ClickHouseUsers[0]; got != "writer" {
		t.Errorf("returned config user = %q, want writer", got)
	}
}

// A malformed config must not cost us authentication: the running mappings stay
// in place and the process keeps serving.
func TestReloadMappingsKeepsRunningMappingsOnBadConfig(t *testing.T) {
	path := writeConfig(t, "reader")
	cfg, authService := startFromConfig(t, path)

	for name, content := range map[string]string{
		"unparseable yaml": "mappings: [oh no\n",
		"fails validation": "oidc:\n  issuer: \"https://issuer.example\"\nmappings: []\n",
		"empty mapping":    "oidc:\n  issuer: \"https://issuer.example\"\nmappings:\n  - namespace: \"analytics\"\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := reloadMappings(path, cfg, authService, metrics.New(), discardLogger()); err == nil {
			t.Errorf("reloadMappings() with %s = nil, want error", name)
		}
		if !authService.Allowed(testIdentity, "reader") {
			t.Fatalf("reader lost authorization after a failed reload (%s)", name)
		}
	}
}

func TestReloadMappingsRecordsCleanReload(t *testing.T) {
	path := writeConfig(t, "reader")
	cfg, authService := startFromConfig(t, path)
	m := metrics.New()

	writeConfigAt(t, path, "writer")
	if _, err := reloadMappings(path, cfg, authService, m, discardLogger()); err != nil {
		t.Fatalf("reloadMappings() = %v", err)
	}

	body := metricsBody(t, m)
	if !strings.Contains(body, `ch_podauth_config_reload_total{result="success"} 1`) {
		t.Errorf("mapping-only reload not counted as a success\n---\n%s", body)
	}
	if !strings.Contains(body, "ch_podauth_config_startup_only_pending 0") {
		t.Errorf("mapping-only reload reported settings as pending\n---\n%s", body)
	}
}

// The issuer is the case that matters. A reload cannot apply it, so the bridge
// keeps trusting the old one until a restart, and operators read these metrics
// to decide whether a config change landed. Reporting this as a clean reload
// would hide a change to the trust boundary.
func TestReloadMappingsFlagsStaleIssuer(t *testing.T) {
	path := writeConfig(t, "reader")
	cfg, authService := startFromConfig(t, path)
	m := metrics.New()

	writeConfigWithIssuer(t, path, "https://rotated.example", "reader")
	if _, err := reloadMappings(path, cfg, authService, m, discardLogger()); err != nil {
		t.Fatalf("reloadMappings() = %v", err)
	}

	body := metricsBody(t, m)
	if !strings.Contains(body, `ch_podauth_config_reload_total{result="partial"} 1`) {
		t.Errorf("issuer change not counted as a partial reload\n---\n%s", body)
	}
	if strings.Contains(body, `ch_podauth_config_reload_total{result="success"}`) {
		t.Errorf("issuer change also counted as a success\n---\n%s", body)
	}
	if !strings.Contains(body, "ch_podauth_config_startup_only_pending 1") {
		t.Errorf("stale issuer not reported as pending\n---\n%s", body)
	}
}

// Guards the signal plumbing itself. Getting this wrong is worse than the
// feature not working: without a handler installed, SIGHUP kills the bridge.
func TestSIGHUPTriggersReload(t *testing.T) {
	path := writeConfig(t, "reader")
	cfg, authService := startFromConfig(t, path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hup, stopReloadSignal := installReloadSignal()
	defer stopReloadSignal()
	go watchReloadSignals(ctx, hup, path, cfg, authService, metrics.New(), discardLogger())

	writeConfigAt(t, path, "writer")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !authService.Allowed(testIdentity, "writer") {
		if time.Now().After(deadline) {
			t.Fatal("mappings were not reloaded within 5s of SIGHUP")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Reverting a startup-only edit has to clear the pending count. Comparing each
// reload against the previous one instead of against startup leaves the gauge
// raised forever, so an operator who fixes a bad issuer sees an alert that only
// a pointless restart can clear. Observed on a live node before this was fixed.
func TestReloadedStartupFieldStopsPendingOnceReverted(t *testing.T) {
	path := writeConfig(t, "reader")
	cfg, authService := startFromConfig(t, path)
	m := metrics.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hup, stopReloadSignal := installReloadSignal()
	defer stopReloadSignal()
	go watchReloadSignals(ctx, hup, path, cfg, authService, m, discardLogger())

	writeConfigWithIssuer(t, path, "https://rotated.example", "reader")
	awaitPending(t, m, 1, "issuer drift was not reported as pending")

	writeConfigWithIssuer(t, path, "https://issuer.example", "reader")
	awaitPending(t, m, 0, "reverting the issuer did not clear the pending count")
}

func awaitPending(t *testing.T, m *metrics.Metrics, want int, msg string) {
	t.Helper()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("ch_podauth_config_startup_only_pending %d", want)
	deadline := time.Now().Add(5 * time.Second)
	for {
		body := metricsBody(t, m)
		if strings.Contains(body, target) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: never saw %q\n---\n%s", msg, target, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var testIdentity = token.Identity{
	Namespace:          "analytics",
	ServiceAccountName: "ch-reader",
	ServiceAccountUID:  "sa-uid",
	PodName:            "reader-0",
	PodUID:             "pod-uid",
}

func startFromConfig(t *testing.T, path string) (config.Config, *auth.Service) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(stubValidator{}, cfg.AuthMappings(), discardLogger(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, authService
}

func writeConfig(t *testing.T, clickhouseUser string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigAt(t, path, clickhouseUser)
	return path
}

func writeConfigAt(t *testing.T, path, clickhouseUser string) {
	t.Helper()
	writeConfigWithIssuer(t, path, "https://issuer.example", clickhouseUser)
}

func writeConfigWithIssuer(t *testing.T, path, issuer, clickhouseUser string) {
	t.Helper()
	content := `oidc:
  issuer: "` + issuer + `"
  audience: "clickhouse-auth"
mappings:
  - namespace: "analytics"
    service_account: "ch-reader"
    clickhouse_users:
      - "` + clickhouseUser + `"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func metricsBody(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

type stubValidator struct{}

func (stubValidator) Validate(context.Context, string) (token.Identity, error) {
	return testIdentity, nil
}
