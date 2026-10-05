package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func TestProductionMiddlewareDoesNotLogOIDCCallbackSecrets(t *testing.T) {
	var output bytes.Buffer
	previousGinWriter := gin.DefaultWriter
	previousLogOutput := log.StandardLogger().Out
	previousLogLevel := log.GetLevel()
	previousGinMode := gin.Mode()
	t.Cleanup(func() {
		gin.DefaultWriter = previousGinWriter
		log.SetOutput(previousLogOutput)
		log.SetLevel(previousLogLevel)
		gin.SetMode(previousGinMode)
	})

	gin.SetMode(gin.TestMode)
	gin.DefaultWriter = &output
	log.SetOutput(&output)
	log.SetLevel(log.TraceLevel)

	router := newRouter(true)
	router.GET(oidcCallbackPath, func(c *gin.Context) {
		c.Status(http.StatusBadRequest)
	})
	router.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	callback := httptest.NewRequest(
		http.MethodGet,
		oidcCallbackPath+"?code=oauth-code-secret&state=oauth-state-secret&verifier=oauth-verifier-secret&nonce=oauth-nonce-secret",
		nil,
	)
	callback.Header.Set("Cookie", "oidc_verifier=oauth-verifier-secret; oidc_nonce=oauth-nonce-secret")
	router.ServeHTTP(httptest.NewRecorder(), callback)

	ordinary := httptest.NewRequest(http.MethodGet, "/health?code=ordinary-query", nil)
	router.ServeHTTP(httptest.NewRecorder(), ordinary)

	logs := output.String()
	for _, secret := range []string{
		"oauth-code-secret",
		"oauth-state-secret",
		"oauth-verifier-secret",
		"oauth-nonce-secret",
	} {
		if strings.Contains(logs, secret) {
			t.Fatalf("OIDC callback secret %q was logged: %s", secret, logs)
		}
	}
	if !strings.Contains(logs, "/health?code=ordinary-query") {
		t.Fatalf("ordinary request was not logged: %s", logs)
	}
}
