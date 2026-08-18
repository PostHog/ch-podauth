//go:build unix

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
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
	content := `oidc:
  issuer: "https://issuer.example"
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

type stubValidator struct{}

func (stubValidator) Validate(context.Context, string) (token.Identity, error) {
	return testIdentity, nil
}
