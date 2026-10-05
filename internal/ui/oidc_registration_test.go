package ui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/config"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/ddvk/rmfakecloud/internal/storage"
	"github.com/gin-gonic/gin"
)

func TestOIDCRejectsUnknownUserWhenRegistrationIsClosed(t *testing.T) {
	storer := newFakeUserStorer()
	app := testUIApp(&config.Config{OIDC: oidcOn(), HTTPSCookie: true}, storer)
	identity := oidcUserIdentity{Value: "newcomer", ClaimName: "preferred_username"}

	_, err := app.getOrProvisionUser("newcomer", identity, oidcClaims{}, nil)

	if !errors.Is(err, errOIDCRegistrationClosed) {
		t.Fatalf("got %v, want errOIDCRegistrationClosed", err)
	}
	if len(storer.registered) != 0 {
		t.Fatal("closed registration provisioned an account")
	}
	if _, err := storer.GetUser("newcomer"); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("closed registration created an account: %v", err)
	}
}

func TestOIDCClosedRegistrationReturnsForbiddenWithoutIssuingSession(t *testing.T) {
	storer := newFakeUserStorer()
	app := testUIApp(&config.Config{OIDC: oidcOn(), HTTPSCookie: true}, storer)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/ui/api/oidc/callback", nil)

	app.completeOIDCLogin(c,
		map[string]any{"preferred_username": "newcomer"},
		oidcClaims{PreferredUsername: "newcomer"},
	)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", recorder.Code)
	}
	if recorder.Header().Get("Set-Cookie") != "" {
		t.Fatal("closed registration issued a web session")
	}
	if len(storer.registered) != 0 {
		t.Fatal("closed registration provisioned an account")
	}
}

func TestOIDCProvisioningOccursWhenRegistrationIsOpen(t *testing.T) {
	storer := newFakeUserStorer()
	app := testUIApp(&config.Config{
		OIDC:             oidcOn(),
		HTTPSCookie:      true,
		RegistrationOpen: true,
	}, storer)
	identity := oidcUserIdentity{Value: "newcomer", ClaimName: "preferred_username"}

	user, err := app.getOrProvisionUser("newcomer", identity, oidcClaims{}, nil)

	if err != nil {
		t.Fatalf("open registration rejected provisioning: %v", err)
	}
	if user == nil || user.ID != "newcomer" || len(storer.registered) != 1 {
		t.Fatalf("unexpected provisioned user: %#v", user)
	}
}

func TestOIDCExistingAdminRemainsUsableWhenRegistrationIsClosed(t *testing.T) {
	user, err := model.NewUser(" Alex ", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	user.IsAdmin = true
	storer := newFakeUserStorer(user)
	app := testUIApp(&config.Config{OIDC: oidcOn(), HTTPSCookie: true}, storer)
	identity := oidcUserIdentity{Value: "Alex", ClaimName: "preferred_username"}

	got, err := app.getOrProvisionUser("alex", identity, oidcClaims{}, nil)

	if err != nil {
		t.Fatalf("existing account was rejected: %v", err)
	}
	if got != user || !got.IsAdmin {
		t.Fatalf("existing admin changed: got %+v", got)
	}
	if len(storer.updated) != 0 {
		t.Fatalf("existing account was unexpectedly updated: %d updates", len(storer.updated))
	}
}

func TestNativePasswordLoginStillNormalizesExistingUser(t *testing.T) {
	user, err := model.NewUser(" Alex ", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	storer := newFakeUserStorer(user)
	app := testUIApp(&config.Config{
		JWTSecretKey: []byte("test-secret"),
		OIDC:         oidcOn(),
	}, storer)
	router := routerForUIApp(t, app)

	response := requestUI(t, router, http.MethodPost, "/ui/api/login", strings.NewReader(`{"email":" ALEX ","password":"hunter2"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("native login returned %d, want 200", response.Code)
	}
	if response.Header().Get("Set-Cookie") == "" {
		t.Fatal("native login did not issue a session")
	}
}
