package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/rorylshanks/ch-podauth/internal/token"
)

func TestServiceAllowsMappedClickHouseUser(t *testing.T) {
	service := newTestService(t, token.Identity{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	})

	decision := service.Authenticate(context.Background(), "reader", "jwt")
	if !decision.Allowed {
		t.Fatalf("Authenticate() allowed = false, reason = %s", decision.Reason)
	}
}

func TestServiceDeniesDisallowedClickHouseUser(t *testing.T) {
	service := newTestService(t, token.Identity{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	})

	decision := service.Authenticate(context.Background(), "admin", "jwt")
	if decision.Allowed || decision.Reason != "user_not_allowed" {
		t.Fatalf("Authenticate() = %+v, want user_not_allowed denial", decision)
	}
}

func TestServiceDeniesUnmappedServiceAccount(t *testing.T) {
	service := newTestService(t, token.Identity{
		Namespace:          "other",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	})

	decision := service.Authenticate(context.Background(), "reader", "jwt")
	if decision.Allowed || decision.Reason != "user_not_allowed" {
		t.Fatalf("Authenticate() = %+v, want user_not_allowed denial", decision)
	}
}

func TestServiceDeniesInvalidToken(t *testing.T) {
	service, err := NewService(fakeValidator{err: errors.New("bad token")}, []Mapping{{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ClickHouseUsers:    []string{"reader"},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}

	decision := service.Authenticate(context.Background(), "reader", "jwt")
	if decision.Allowed || decision.Reason != "invalid_token" {
		t.Fatalf("Authenticate() = %+v, want invalid_token denial", decision)
	}
}

func TestSetMappingsSwapsTheAuthorizationTable(t *testing.T) {
	id := token.Identity{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	}
	service := newTestService(t, id)

	if decision := service.Authenticate(context.Background(), "writer", "jwt"); decision.Allowed {
		t.Fatal("Authenticate() allowed writer before it was mapped")
	}

	if err := service.SetMappings([]Mapping{{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ClickHouseUsers:    []string{"writer"},
	}}); err != nil {
		t.Fatalf("SetMappings() = %v", err)
	}

	if decision := service.Authenticate(context.Background(), "writer", "jwt"); !decision.Allowed {
		t.Fatalf("Authenticate() after reload = %+v, want allowed", decision)
	}
	// The old table is replaced, not merged, so a user dropped from the config
	// stops authenticating.
	if decision := service.Authenticate(context.Background(), "reader", "jwt"); decision.Allowed {
		t.Fatal("Authenticate() still allowed reader after it was dropped from the mappings")
	}
	if got := service.MappingCount(); got != 1 {
		t.Fatalf("MappingCount() = %d, want 1", got)
	}
}

func TestSetMappingsRejectsBadMappingsAndKeepsServing(t *testing.T) {
	id := token.Identity{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	}
	service := newTestService(t, id)

	for name, mappings := range map[string][]Mapping{
		"empty":              {},
		"missing namespace":  {{ServiceAccountName: "ch-reader", ClickHouseUsers: []string{"reader"}}},
		"no clickhouse user": {{Namespace: "analytics", ServiceAccountName: "ch-reader"}},
		"blank user":         {{Namespace: "analytics", ServiceAccountName: "ch-reader", ClickHouseUsers: []string{"  "}}},
	} {
		if err := service.SetMappings(mappings); err == nil {
			t.Errorf("SetMappings(%s) = nil, want error", name)
		}
		if decision := service.Authenticate(context.Background(), "reader", "jwt"); !decision.Allowed {
			t.Fatalf("reader denied after a rejected %s reload: %+v", name, decision)
		}
	}
}

// Reloads land while binds are in flight, so the swap has to be race-free.
func TestSetMappingsIsSafeDuringConcurrentBinds(t *testing.T) {
	id := token.Identity{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	}
	service := newTestService(t, id)

	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					// "reader" is in every table the reloader installs, so a
					// denial here means a torn or empty read, not a policy change.
					if decision := service.Authenticate(context.Background(), "reader", "jwt"); !decision.Allowed {
						t.Errorf("Authenticate() denied a permanently mapped user: %+v", decision)
						return
					}
				}
			}
		}()
	}

	for i := range 200 {
		users := []string{"reader"}
		if i%2 == 0 {
			users = append(users, "writer")
		}
		if err := service.SetMappings([]Mapping{{
			Namespace:          "analytics",
			ServiceAccountName: "ch-reader",
			ClickHouseUsers:    users,
		}}); err != nil {
			t.Fatalf("SetMappings() = %v", err)
		}
	}
	close(done)
	wg.Wait()
}

func newTestService(t *testing.T, id token.Identity) *Service {
	t.Helper()
	service, err := NewService(fakeValidator{id: id}, []Mapping{{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ClickHouseUsers:    []string{"reader", "readonly"},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fakeValidator struct {
	id  token.Identity
	err error
}

func (v fakeValidator) Validate(context.Context, string) (token.Identity, error) {
	return v.id, v.err
}
