package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/config"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/gin-gonic/gin"
)

func TestEmbeddedIndexFallbackServesOIDCPaths(t *testing.T) {
	cfg := &config.Config{
		JWTSecretKey: []byte("test-secret"),
		OIDC:         oidcOn(),
		HTTPSCookie:  false,
	}
	cfg.OIDC.DisableLocalLogin = true
	app := New(cfg, newFakeUserStorer(), nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	app.RegisterRoutes(router)

	user := &model.User{ID: "alex", Email: "alex@example.com"}
	sessionRecorder := httptest.NewRecorder()
	sessionContext, _ := gin.CreateTestContext(sessionRecorder)
	sessionContext.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := app.issueWebSession(sessionContext, user); err != nil {
		t.Fatal(err)
	}
	sessionCookies := (&http.Response{Header: sessionRecorder.Header()}).Cookies()
	if len(sessionCookies) != 1 {
		t.Fatalf("issued %d session cookies, want 1", len(sessionCookies))
	}

	for _, path := range []string{"/oidc-success", "/"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.AddCookie(sessionCookies[0])
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("GET %s returned %d, want 200", path, recorder.Code)
			}
			if location := recorder.Header().Get("Location"); location != "" {
				t.Fatalf("GET %s redirected to %q", path, location)
			}
			if !strings.Contains(recorder.Body.String(), "<html") {
				t.Fatalf("GET %s did not return embedded HTML", path)
			}
		})
	}
}
