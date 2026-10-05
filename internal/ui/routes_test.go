package ui

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/config"
	log "github.com/sirupsen/logrus"
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

func TestPublicAuthConfigExposesOnlyLoginChoices(t *testing.T) {
	cfg := uiRouteConfig()
	cfg.OIDC.DisplayName = "Login with Authentik"
	app := testUIApp(cfg, newFakeUserStorer())
	router := routerForUIApp(t, app)

	response := requestUI(t, router, http.MethodGet, "/ui/api/auth/config", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("auth config returned %d, want 200", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{"\"oidc_enabled\":true", "\"oidc_login_url\":\"/ui/api/oidc/login\"", "\"oidc_display_name\":\"Login with Authentik\"", "\"local_login_enabled\":true"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("auth config omitted %s: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"client-secret", "sso.example.com"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("auth config leaked %s: %s", forbidden, body)
		}
	}
}

func TestOIDCProviderFailureIsRequestScoped(t *testing.T) {
	cfg := uiRouteConfig()
	cfg.OIDC.ProviderURL = "https://127.0.0.1:1"
	app := testUIApp(cfg, newFakeUserStorer())
	router := routerForUIApp(t, app)

	response := requestUI(t, router, http.MethodGet, "/ui/api/oidc/login", nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("provider failure returned %d, want 503", response.Code)
	}
	response = requestUI(t, router, http.MethodGet, "/ui/api/auth/config", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("native UI stopped responding after provider failure: %d", response.Code)
	}
	response = requestUI(t, router, http.MethodPost, "/ui/api/login", nil)
	if response.Code == http.StatusNotFound {
		t.Fatal("native login route disappeared after provider failure")
	}
}

func TestUnknownOIDCCallbackDoesNotLogOAuthQuery(t *testing.T) {
	var output bytes.Buffer
	previousOutput := log.StandardLogger().Out
	t.Cleanup(func() { log.SetOutput(previousOutput) })
	log.SetOutput(&output)

	app := testUIApp(uiRouteConfig(), newFakeUserStorer())
	router := routerForUIApp(t, app)
	request := requestUI(t, router, http.MethodPost, oidcCallbackPath+"?code=oauth-code-secret&state=oauth-state-secret", nil)
	if request.Code != http.StatusNotFound {
		t.Fatalf("unknown callback method returned %d, want 404", request.Code)
	}
	if strings.Contains(output.String(), "oauth-code-secret") || strings.Contains(output.String(), "oauth-state-secret") {
		t.Fatalf("unknown callback request leaked OAuth query: %s", output.String())
	}
}
