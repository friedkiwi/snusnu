package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCompiledRouterVersionMatchesCargoManifest(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join("..", "..", "..", "sna_router", "crates", "snusnu-router", "Cargo.toml"))
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^version = "([^"]+)"$`).FindStringSubmatch(string(manifest))
	if len(match) != 2 || match[1] != latestSnaRouterVersion {
		t.Fatalf("compiled router version %q differs from Cargo manifest %q", latestSnaRouterVersion, match)
	}
}

func TestClientSoftwarePolicy(t *testing.T) {
	policy := softwarePolicy{minimumVersion: "1.2.0", blockedVersions: map[string]bool{"1.3.0": true}}
	for _, tc := range []struct {
		name, version, latest, update, errorContains string
	}{
		{"sna_router", "1.2.0", "1.4.0", "1.4.0", ""},
		{"sna_router", "1.4.0", "1.4.0", "", ""},
		{"sna_router", "2.0.0", "1.4.0", "", ""},
		{"sna_router", "1.1.9", "1.4.0", "", "blocked"},
		{"sna_router", "1.3.0", "1.4.0", "", "blocked"},
		{"sna_router", "unknown", "1.4.0", "", "invalid"},
	} {
		got, err := evaluateSnaRouter(clientSoftware{name: tc.name, version: tc.version}, policy, tc.latest)
		if tc.errorContains != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errorContains) {
				t.Fatalf("version %q: expected %s, got %v", tc.version, tc.errorContains, err)
			}
		} else if err != nil || got.updateVersion != tc.update {
			t.Fatalf("version %q: update %q, error %v", tc.version, got.updateVersion, err)
		}
	}
	req := httptest.NewRequest("GET", "/router/v1/ws", nil)
	req.Header.Set(softwareNameHeader, "another-router")
	req.Header.Set(softwareVersionHeader, "0.0.1+custom")
	got, err := inspectClientSoftware(req)
	if err != nil || got.name != "another-router" || got.version != "0.0.1+custom" || got.updateVersion != "" {
		t.Fatalf("third-party client: %+v, %v", got, err)
	}
}
