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
