package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestNonReloadableDiffIgnoresMappingChanges(t *testing.T) {
	running := Default()
	running.OIDC.Issuer = "https://issuer.example"
	next := running
	next.Mappings = []MappingConfig{{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ClickHouseUsers:    []string{"reader"},
	}}

	if changed := NonReloadableDiff(running, next); len(changed) != 0 {
		t.Fatalf("NonReloadableDiff() = %v, want empty for a mappings-only edit", changed)
	}
}

func TestNonReloadableDiffNamesStartupOnlyEdits(t *testing.T) {
	running := Default()
	running.OIDC.Issuer = "https://issuer.example"
	next := running
	next.OIDC.Issuer = "https://other.example"
	next.LDAP.ListenAddr = "127.0.0.1:2389"

	changed := NonReloadableDiff(running, next)
	want := []string{"ldap.listen_addr", "oidc.issuer"}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("NonReloadableDiff() = %v, want %v", changed, want)
	}
}

// A field missing from the table is an edit the operator would never be told
// was ignored, which is the exact surprise the diff exists to prevent.
func TestStartupOnlyFieldsCoversEveryStartupSection(t *testing.T) {
	table := startupOnlyFields(Default())
	sections := map[string]any{
		"ldap":    LDAPConfig{},
		"http":    HTTPConfig{},
		"oidc":    OIDCConfig{},
		"logging": LoggingConfig{},
	}

	covered := 0
	for section, sample := range sections {
		typ := reflect.TypeOf(sample)
		for i := range typ.NumField() {
			yamlName := strings.Split(typ.Field(i).Tag.Get("yaml"), ",")[0]
			name := section + "." + yamlName
			if _, ok := table[name]; !ok {
				t.Errorf("startupOnlyFields is missing %q; a reload would ignore it silently", name)
			}
			covered++
		}
	}
	if len(table) != covered {
		t.Errorf("startupOnlyFields has %d entries for %d config fields; it lists something that no longer exists", len(table), covered)
	}
}
