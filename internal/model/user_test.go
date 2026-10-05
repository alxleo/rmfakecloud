package model

import "testing"

func TestNewUserKeepsLegacyIdentifierCasing(t *testing.T) {
	user, err := NewUser("MiXeDUser", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "MiXeDUser" || user.Email != "MiXeDUser" {
		t.Fatalf("NewUser changed legacy identifier casing: ID=%q Email=%q", user.ID, user.Email)
	}
}

func TestLocalReturnVersionPolicyIsOptInAndSurvivesProfileRoundTrip(t *testing.T) {
	legacy := []byte("id: alex\nintegrations:\n  - id: existing\n    provider: localfs\n    path: /data/legacy\n")
	user, err := DeserializeUser(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if len(user.Integrations) != 1 || user.Integrations[0].PreserveVersions {
		t.Fatal("legacy profile behavior changed")
	}
	user.Integrations[0].PreserveVersions = true
	serialized, err := user.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DeserializeUser(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Integrations[0].PreserveVersions || restored.Integrations[0].ID != "existing" || restored.Integrations[0].Path != "/data/legacy" {
		t.Fatal("return policy or existing identity lost")
	}
}
