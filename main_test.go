package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPluginRegistrationDeclaresOnlyManagementAPI(t *testing.T) {
	registration := pluginRegistration()
	if registration.Metadata.Name == "" || registration.Metadata.Version == "" ||
		registration.Metadata.Author == "" || registration.Metadata.GitHubRepository == "" {
		t.Fatalf("host-required metadata is incomplete: %+v", registration.Metadata)
	}
	raw, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"management_api":true`) {
		t.Fatalf("management capability missing: %s", text)
	}
	for _, unexpected := range []string{"usage_plugin", "scheduler"} {
		if strings.Contains(text, unexpected) {
			t.Fatalf("unexpected capability %q: %s", unexpected, text)
		}
	}
}

func TestManagementRegistrationUsesCanonicalJSONKeys(t *testing.T) {
	raw, err := json.Marshal(managementRegistration())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"resources"`) || strings.Contains(text, `"Resources"`) {
		t.Fatalf("unexpected registration JSON: %s", text)
	}
}

func TestManagementOpenRoute(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"Method":  "GET",
		"Path":    "/v0/resource/plugins/auth-inspect/open",
		"Headers": map[string][]string{},
		"Query":   map[string][]string{},
		"Body":    []byte{},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := handleManagement(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(response), `"StatusCode":200`) {
		t.Fatalf("unexpected management response: %s", response)
	}
}
