package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExposesMetrics(t *testing.T) {
	m := New()
	m.ObserveBind(true, "success")
	m.ObserveBind(false, "user_not_allowed")
	m.ObserveBindDuration(0.123)
	m.ObserveConnectionRejected()
	m.ObserveProtocolError()
	m.ObserveRequestTooLarge()
	m.ObserveJWKSRefresh(true, 3)
	m.ObserveJWKSRefresh(false, 0)
	m.ObserveConfigReloadSuccess(7, 0)
	m.ObserveConfigReloadFailure()
	m.IncActiveConnections()
	m.SetMaxConnections(256)

	body := scrape(t, m)

	want := []string{
		"ch_podauth_ldap_binds_total 2",
		"ch_podauth_ldap_bind_success_total 1",
		"ch_podauth_ldap_bind_failure_total 1",
		`ch_podauth_ldap_bind_failures_by_reason_total{reason="user_not_allowed"} 1`,
		"ch_podauth_ldap_request_too_large_total 1",
		"ch_podauth_ldap_protocol_errors_total 1",
		"ch_podauth_ldap_connections_rejected_total 1",
		"ch_podauth_bind_duration_seconds_count 1",
		`ch_podauth_jwks_refresh_total{result="success"} 1`,
		`ch_podauth_jwks_refresh_total{result="failure"} 1`,
		"ch_podauth_jwks_keys 3",
		`ch_podauth_config_reload_total{result="success"} 1`,
		`ch_podauth_config_reload_total{result="failure"} 1`,
		// A failed reload leaves the previous mapping count in place.
		"ch_podauth_mappings_loaded 7",
		"ch_podauth_config_startup_only_pending 0",
		"ch_podauth_active_connections 1",
		"ch_podauth_max_connections 256",
		// Go runtime / process collectors registered by New().
		"go_goroutines",
		"process_start_time_seconds",
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("metrics output missing %q\n---\n%s", w, body)
		}
	}
}

// A reload that could not apply every setting must not read as clean. The
// process is serving a config that differs from the one on disk until it
// restarts, and the gauge is what makes that state alertable.
func TestPartialReloadIsDistinguishableFromSuccess(t *testing.T) {
	m := New()
	m.ObserveConfigReloadSuccess(4, 2)

	body := scrape(t, m)
	for _, w := range []string{
		`ch_podauth_config_reload_total{result="partial"} 1`,
		"ch_podauth_config_startup_only_pending 2",
		"ch_podauth_mappings_loaded 4",
	} {
		if !strings.Contains(body, w) {
			t.Errorf("metrics output missing %q\n---\n%s", w, body)
		}
	}
	if strings.Contains(body, `ch_podauth_config_reload_total{result="success"}`) {
		t.Errorf("partial reload also counted as a success\n---\n%s", body)
	}

	// The stale settings are still stale after a later failure, so the pending
	// count has to survive it.
	m.ObserveConfigReloadFailure()
	if body := scrape(t, m); !strings.Contains(body, "ch_podauth_config_startup_only_pending 2") {
		t.Errorf("failed reload cleared the pending gauge\n---\n%s", body)
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}
