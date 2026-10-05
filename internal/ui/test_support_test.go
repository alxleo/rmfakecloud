package ui

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/ddvk/rmfakecloud/internal/config"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/ddvk/rmfakecloud/internal/storage"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type fakeUserStorer struct {
	users      map[string]*model.User
	registered []*model.User
	updated    []*model.User
}

func newFakeUserStorer(users ...*model.User) *fakeUserStorer {
	storer := &fakeUserStorer{users: make(map[string]*model.User)}
	for _, user := range users {
		storer.users[user.ID] = user
	}
	return storer
}

func (s *fakeUserStorer) GetUsers() ([]*model.User, error) {
	users := make([]*model.User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users, nil
}

func (s *fakeUserStorer) GetUser(id string) (*model.User, error) {
	user, ok := s.users[model.NormalizeUserID(id)]
	if !ok {
		return nil, storage.ErrUserNotFound
	}
	return user, nil
}

func (s *fakeUserStorer) RegisterUser(user *model.User) error {
	if _, ok := s.users[user.ID]; ok {
		return errors.New("user already exists")
	}
	s.users[user.ID] = user
	s.registered = append(s.registered, user)
	return nil
}

func (s *fakeUserStorer) UpdateUser(user *model.User) error {
	s.users[user.ID] = user
	s.updated = append(s.updated, user)
	return nil
}

func (s *fakeUserStorer) RemoveUser(id string) error {
	delete(s.users, model.NormalizeUserID(id))
	return nil
}

func oidcOn() config.OIDCConfig {
	return config.OIDCConfig{
		ProviderURL:  "https://sso.example.com",
		ClientID:     "rmfakecloud",
		ClientSecret: "client-secret",
		RedirectURL:  "https://cloud.example.com/ui/api/oidc/callback",
		UserIDClaim:  "preferred_username",
	}
}

func testUIApp(cfg *config.Config, storer storage.UserStorer) *ReactAppWrapper {
	return &ReactAppWrapper{
		fs: http.FS(fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("index")},
		}),
		prefix:     "/assets",
		cfg:        cfg,
		userStorer: storer,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://sso.example.com/authorize",
			},
		},
	}
}

func routerForUIApp(t *testing.T, app *ReactAppWrapper) *gin.Engine {
	t.Helper()
	router := gin.New()
	app.RegisterRoutes(router)
	return router
}

func requestUI(t *testing.T, router http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, body)
	router.ServeHTTP(recorder, request)
	return recorder
}
