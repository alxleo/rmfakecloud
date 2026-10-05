package ui

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/common"
	"github.com/ddvk/rmfakecloud/internal/config"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

func TestReturnDownloadsKeepPDFBytesAndOwnerSession(t *testing.T) {
	root := t.TempDir()
	filename := "Walkthrough (2026-10-05 14-00-00).pdf"
	payload := []byte("%PDF-1.7\nsource tables and rendered ink\n%%EOF")
	require.NoError(t, os.WriteFile(filepath.Join(root, filename), payload, 0600))
	cfg := &config.Config{JWTSecretKey: []byte("test secret"), OIDC: oidcOn()}
	destination := model.IntegrationConfig{ID: "owner-returns", Provider: "localfs", Name: "Laptop Returns", Path: root, PreserveVersions: true}
	app := testUIApp(cfg, newFakeUserStorer(&model.User{ID: "alex", Integrations: []model.IntegrationConfig{destination}}, &model.User{ID: "other"}))
	router := routerForUIApp(t, app)
	fileID := base64.URLEncoding.EncodeToString([]byte("/" + filename))
	url := "/ui/api/integrations/owner-returns/download/" + fileID
	request := func(uid, url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		if uid != "" {
			token, err := common.SignClaims(&WebUserClaims{UserID: uid, RegisteredClaims: jwt.RegisteredClaims{Audience: []string{WebUsage}}}, cfg.JWTSecretKey)
			require.NoError(t, err)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	opened := request("alex", url)
	require.Equal(t, http.StatusOK, opened.Code)
	require.Equal(t, payload, opened.Body.Bytes())
	require.Equal(t, "application/pdf", opened.Header().Get("Content-Type"))
	require.Contains(t, opened.Header().Get("Content-Disposition"), "inline;")
	saved := request("alex", url+"?download=true")
	require.Equal(t, http.StatusOK, saved.Code)
	require.Contains(t, saved.Header().Get("Content-Disposition"), "attachment;")
	require.Contains(t, saved.Header().Get("Content-Disposition"), filename)
	for _, uid := range []string{"", "other"} {
		response := request(uid, url)
		require.NotEqual(t, http.StatusOK, response.Code)
		require.NotContains(t, response.Body.String(), string(payload))
	}
	listing := request("alex", "/ui/api/integrations/owner-returns/explore/root")
	require.Equal(t, http.StatusOK, listing.Code)
	require.Contains(t, listing.Body.String(), strings.TrimSuffix(filename, ".pdf"))
}
