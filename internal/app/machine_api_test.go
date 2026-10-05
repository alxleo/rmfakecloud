package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/common"
	"github.com/ddvk/rmfakecloud/internal/config"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/ddvk/rmfakecloud/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type machineUserStorer struct {
	user *model.User
}

func (s *machineUserStorer) GetUsers() ([]*model.User, error) {
	return []*model.User{s.user}, nil
}

func (s *machineUserStorer) GetUser(id string) (*model.User, error) {
	if s.user == nil || s.user.ID != id {
		return nil, storage.ErrUserNotFound
	}
	return s.user, nil
}

func (s *machineUserStorer) RegisterUser(*model.User) error { return nil }

func (s *machineUserStorer) UpdateUser(*model.User) error { return nil }

func (s *machineUserStorer) RemoveUser(string) error { return nil }

func TestDeviceBearerAPIIsUnaffectedByOIDCLocalLoginFlag(t *testing.T) {
	secret := []byte("test-secret")
	user := &model.User{ID: "alex", Email: "alex@example.com", Sync15: true}
	app := &App{
		cfg: &config.Config{
			JWTSecretKey: secret,
			StorageURL:   "https://cloud.example.com",
			OIDC: config.OIDCConfig{
				ProviderURL:       "https://sso.example.com",
				ClientID:          "rmfakecloud",
				ClientSecret:      "client-secret",
				RedirectURL:       "https://cloud.example.com/ui/api/oidc/callback",
				DisableLocalLogin: true,
			},
		},
		userStorer: &machineUserStorer{user: user},
	}

	deviceToken, err := common.SignClaims(&DeviceClaims{
		UserID:     user.ID,
		DeviceDesc: "remarkable2",
		DeviceID:   "device-1",
		StandardClaims: jwt.StandardClaims{
			Audience: APIUsage,
		},
	}, secret)
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	app.registerRoutes(router)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/token/json/2/user/new", nil)
	request.Header.Set("Authorization", "Bearer "+deviceToken)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("device bearer token renewal returned %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.Len() == 0 {
		t.Fatal("device bearer token renewal returned an empty token")
	}
}
