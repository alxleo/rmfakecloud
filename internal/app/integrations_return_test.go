package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/common"
	"github.com/ddvk/rmfakecloud/internal/config"
	"github.com/ddvk/rmfakecloud/internal/messages"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

func TestNativeV2ReturnsKeepDeviceRenderedPDFAndOwnership(t *testing.T) {
	secret := []byte("test secret")
	destination := model.IntegrationConfig{ID: "owner-return", Name: "Laptop Returns", Provider: "localfs", Path: t.TempDir(), PreserveVersions: true}
	app := &App{cfg: &config.Config{JWTSecretKey: secret}, userStorer: &machineUserStorer{user: &model.User{ID: "alex", Integrations: []model.IntegrationConfig{destination}}}}
	router := gin.New()
	app.registerRoutes(router)
	request := func(uid, method, path, body string) *httptest.ResponseRecorder {
		token, err := common.SignClaims(&UserClaims{Version: tokenVersion, Profile: Auth0profile{UserID: uid}, StandardClaims: jwt.StandardClaims{Audience: APIUsage}}, secret)
		require.NoError(t, err)
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "xochitl/3.27.0.97")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	instances := request("alex", "GET", "/integrations/v2/instances", "")
	require.Equal(t, http.StatusOK, instances.Code)
	var response messages.IntegrationsResponse
	require.NoError(t, json.Unmarshal(instances.Body.Bytes(), &response))
	require.Len(t, response.Integrations, 1)
	require.Equal(t, "Storage", response.Integrations[0].ProviderType)
	require.Equal(t, "Dropbox", response.Integrations[0].Provider)
	payload := "%PDF-1.7\nbackground text and device-rendered ink\n%%EOF"
	upload := request("alex", "POST", "/integrations/v2/storage/owner-return/files/root?name=Walkthrough&fileType=pdf", payload)
	require.Equal(t, http.StatusOK, upload.Code)
	var uploaded struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(upload.Body.Bytes(), &uploaded))
	download := request("alex", "GET", "/integrations/v2/storage/owner-return/files/"+uploaded.ID, "")
	require.Equal(t, http.StatusOK, download.Code)
	require.Equal(t, payload, download.Body.String())
	other := request("other", "GET", "/integrations/v2/storage/owner-return/files/"+uploaded.ID, "")
	require.NotEqual(t, http.StatusOK, other.Code)
	require.NotContains(t, other.Body.String(), payload)
	// Native paths and the old version both use the same owner-confined provider.
	legacy := request("alex", "GET", "/integrations/v1/owner-return/files/"+uploaded.ID, "")
	require.Equal(t, http.StatusOK, legacy.Code)
	require.Equal(t, payload, legacy.Body.String())
	traversal := base64.URLEncoding.EncodeToString([]byte("/../private.pdf"))
	escaped := request("alex", "GET", "/integrations/v2/storage/owner-return/files/"+traversal, "")
	require.NotEqual(t, http.StatusOK, escaped.Code)
}
