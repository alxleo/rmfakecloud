package ui

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/config"
)

func uiRouteConfig() *config.Config {
	return &config.Config{
		JWTSecretKey: []byte("test-secret"),
		OIDC:         oidcOn(),
	}
}

func TestOIDCEnabledKeepsLocalLoginByDefault(t *testing.T) {
	app := testUIApp(uiRouteConfig(), newFakeUserStorer())
	router := routerForUIApp(t, app)

	for _, path := range []string{"/ui/api/login", "/ui/api/register", "/ui/api/oidc/login"} {
		method := http.MethodPost
		if strings.HasSuffix(path, "/oidc/login") {
			method = http.MethodGet
		}
		response := requestUI(t, router, method, path, nil)
		if response.Code == http.StatusNotFound {
			t.Errorf("%s %s was not registered", method, path)
		}
	}
}

func TestOIDCDisableLocalLoginRemovesPasswordRoutes(t *testing.T) {
	cfg := uiRouteConfig()
	cfg.OIDC.DisableLocalLogin = true
	app := testUIApp(cfg, newFakeUserStorer())
	router := routerForUIApp(t, app)

	for _, path := range []string{"/ui/api/login", "/ui/api/register"} {
		response := requestUI(t, router, http.MethodPost, path, nil)
		if response.Code != http.StatusNotFound {
			t.Errorf("POST %s returned %d, want 404", path, response.Code)
		}
	}
	response := requestUI(t, router, http.MethodGet, "/ui/api/oidc/login", nil)
	if response.Code == http.StatusNotFound {
		t.Fatal("OIDC login route was removed with local login")
	}
}

func TestOIDCDisableLocalLoginRedirectsUnauthenticatedPages(t *testing.T) {
	cfg := uiRouteConfig()
	cfg.OIDC.DisableLocalLogin = true
	app := testUIApp(cfg, newFakeUserStorer())
	router := routerForUIApp(t, app)

	response := requestUI(t, router, http.MethodGet, "/documents", nil)
	if response.Code != http.StatusFound {
		t.Fatalf("GET /documents returned %d, want 302", response.Code)
	}
	if location := response.Header().Get("Location"); location != "/ui/api/oidc/login" {
		t.Fatalf("redirect location = %q, want /ui/api/oidc/login", location)
	}

	response = requestUI(t, router, http.MethodGet, "/oidc-success", nil)
	if response.Code == http.StatusFound && response.Header().Get("Location") == "/ui/api/oidc/login" {
		t.Fatal("GET /oidc-success was redirected back to OIDC login")
	}
}

func TestOIDCDisabledKeepsNativeLoginRoutes(t *testing.T) {
	cfg := &config.Config{JWTSecretKey: []byte("test-secret")}
	app := testUIApp(cfg, newFakeUserStorer())
	router := routerForUIApp(t, app)

	response := requestUI(t, router, http.MethodPost, "/ui/api/login", nil)
	if response.Code == http.StatusNotFound {
		t.Fatal("native login route was not registered when OIDC is disabled")
	}
}
