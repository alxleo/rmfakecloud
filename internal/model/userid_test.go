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

func TestNormalizeUserIDIsOIDCScoped(t *testing.T) {
	if got := NormalizeUserID("  MiXeD-User  "); got != "mixed-user" {
		t.Fatalf("NormalizeUserID() = %q, want mixed-user", got)
	}
	if got := NormalizeUserID("alice/bob"); got != "alicebob" {
		t.Fatalf("NormalizeUserID() = %q, want alicebob", got)
	}
	if got := NormalizeUserID("..//"); got != "" {
		t.Fatalf("NormalizeUserID() = %q, want empty", got)
	}
}
