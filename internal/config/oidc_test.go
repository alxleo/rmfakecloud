package config

import (
	"strings"
	"testing"
)

func fullOIDCConfig() OIDCConfig {
	return OIDCConfig{
		ProviderURL:  "https://sso.example.com",
		ClientID:     "rmfakecloud",
		ClientSecret: "client-secret",
		RedirectURL:  "https://cloud.example.com/ui/api/oidc/callback",
	}
}

func TestOIDCLocalLoginEnabledByDefault(t *testing.T) {
	cfg := fullOIDCConfig()
	if !cfg.LocalLoginEnabled() {
		t.Fatal("local login is disabled by default")
	}
}

func TestOIDCDisableLocalLoginOnlyAppliesWhenOIDCIsEnabled(t *testing.T) {
	cfg := OIDCConfig{DisableLocalLogin: true}
	if !cfg.LocalLoginEnabled() {
		t.Fatal("disabled OIDC configuration locked out local login")
	}

	cfg = fullOIDCConfig()
	cfg.DisableLocalLogin = true
	if cfg.LocalLoginEnabled() {
		t.Fatal("OIDC_DISABLE_LOCAL_LOGIN did not disable local login")
	}
}

func TestOIDCFromEnvReadsDisableLocalLogin(t *testing.T) {
	for _, name := range []string{
		EnvOIDCProviderURL,
		EnvOIDCClientID,
		EnvOIDCClientSecret,
		EnvOIDCRedirectURL,
	} {
		t.Setenv(name, "configured")
	}
	t.Setenv(EnvOIDCRedirectURL, fullOIDCConfig().RedirectURL)
	t.Setenv(EnvOIDCDisableLocalLogin, "true")

	cfg := FromEnv()
	if !cfg.OIDC.Enabled() || cfg.OIDC.LocalLoginEnabled() {
		t.Fatalf("OIDC env configuration did not disable local login: %+v", cfg.OIDC)
	}
}

func TestEnvVarsDocumentsDisableLocalLogin(t *testing.T) {
	if !strings.Contains(EnvVars(), EnvOIDCDisableLocalLogin) {
		t.Fatalf("EnvVars omitted %s", EnvOIDCDisableLocalLogin)
	}
}
