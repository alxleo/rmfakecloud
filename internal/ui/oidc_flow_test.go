package ui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ddvk/rmfakecloud/internal/config"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type fakeOIDCProvider struct {
	server        *httptest.Server
	key           *rsa.PrivateKey
	badKey        *rsa.PrivateKey
	mu            sync.Mutex
	nonce         string
	codeChallenge string
	redirectURI   string
	username      string
	mode          string
}

func newFakeOIDCProvider(t *testing.T, username, mode string) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeOIDCProvider{key: key, badKey: badKey, username: username, mode: mode}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.handle))
	return provider
}

func (p *fakeOIDCProvider) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		p.discovery(w)
	case "/authorize":
		p.authorize(w, r)
	case "/token":
		p.token(w, r)
	case "/jwks":
		p.jwks(w)
	default:
		http.NotFound(w, r)
	}
}

func (p *fakeOIDCProvider) discovery(w http.ResponseWriter) {
	issuer := p.server.URL
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *fakeOIDCProvider) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	p.mu.Lock()
	p.nonce = query.Get("nonce")
	p.codeChallenge = query.Get("code_challenge")
	p.redirectURI = query.Get("redirect_uri")
	p.mu.Unlock()
	redirect, err := url.Parse(p.redirectURI)
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	values := redirect.Query()
	values.Set("code", "authorization-code")
	values.Set("state", query.Get("state"))
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *fakeOIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Form.Get("code") != "authorization-code" {
		http.Error(w, "bad code", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	nonce := p.nonce
	challenge := p.codeChallenge
	mode := p.mode
	username := p.username
	p.mu.Unlock()
	verifier := r.Form.Get("code_verifier")
	digest := sha256.Sum256([]byte(verifier))
	if mode == "pkce" || base64.RawURLEncoding.EncodeToString(digest[:]) != challenge {
		http.Error(w, "bad pkce", http.StatusBadRequest)
		return
	}
	if mode == "nonce" {
		nonce = "wrong-nonce"
	}
	signingKey := p.key
	if mode == "signature" {
		signingKey = p.badKey
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "test-key"),
	)
	if err != nil {
		http.Error(w, "signer failed", http.StatusInternalServerError)
		return
	}
	idToken, err := jwt.Signed(signer).Claims(map[string]any{
		"iss":                p.server.URL,
		"sub":                username,
		"aud":                "rmfakecloud",
		"exp":                time.Now().Add(5 * time.Minute).Unix(),
		"iat":                time.Now().Unix(),
		"nonce":              nonce,
		"preferred_username": username,
		"email":              username + "@example.com",
		"email_verified":     true,
		"name":               username,
	}).Serialize()
	if err != nil {
		http.Error(w, "token failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": "access-token",
		"token_type":   "Bearer",
		"id_token":     idToken,
	})
}

func (p *fakeOIDCProvider) jwks(w http.ResponseWriter) {
	publicKey := jose.JSONWebKey{
		Key:       &p.key.PublicKey,
		KeyID:     "test-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
}

type oidcTestRig struct {
	provider *fakeOIDCProvider
	cloud    *httptest.Server
	client   *http.Client
}

func newOIDCTestRig(t *testing.T, username, mode string) *oidcTestRig {
	t.Helper()
	provider := newFakeOIDCProvider(t, username, mode)
	user, err := model.NewUser("alex", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	storer := newFakeUserStorer(user)
	app := testUIApp(&config.Config{
		JWTSecretKey: []byte("test-secret"),
		HTTPSCookie:  true,
		OIDC: config.OIDCConfig{
			ProviderURL:  provider.server.URL,
			ClientID:     "rmfakecloud",
			ClientSecret: "client-secret",
			RedirectURL:  "https://cloud.example.test/ui/api/oidc/callback",
			UserIDClaim:  "preferred_username",
		},
	}, storer)
	cloud := httptest.NewTLSServer(routerForUIApp(t, app))
	roots := x509.NewCertPool()
	roots.AddCert(provider.server.Certificate())
	roots.AddCert(cloud.Certificate())
	app.oidcHTTPClient = &http.Client{
		Timeout:   oidcRequestTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &oidcTestRig{
		provider: provider,
		cloud:    cloud,
		client: &http.Client{
			Jar:       jar,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (r *oidcTestRig) close() {
	r.cloud.Close()
	r.provider.server.Close()
}

func (r *oidcTestRig) begin(t *testing.T) (*http.Response, *url.URL) {
	t.Helper()
	response, err := r.client.Get(r.cloud.URL + "/ui/api/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("OIDC login returned %d: %s", response.StatusCode, body)
	}
	authURL, err := response.Location()
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, authURL
}

func (r *oidcTestRig) callback(t *testing.T, authURL *url.URL) *http.Response {
	t.Helper()
	providerResponse, err := r.client.Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer providerResponse.Body.Close()
	callbackURL, err := providerResponse.Location()
	if err != nil {
		t.Fatal(err)
	}
	cloudURL, err := url.Parse(r.cloud.URL)
	if err != nil {
		t.Fatal(err)
	}
	callbackURL.Scheme = cloudURL.Scheme
	callbackURL.Host = cloudURL.Host
	response, err := r.client.Get(cloudURL.String() + callbackURL.RequestURI())
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestOIDCTLSJourneyAndProtocolGuards(t *testing.T) {
	t.Run("signed TLS journey and logout", func(t *testing.T) {
		trig := newOIDCTestRig(t, "alex", "")
		defer trig.close()
		_, authURL := trig.begin(t)
		response := trig.callback(t, authURL)
		response.Body.Close()
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != oidcSuccessPath {
			t.Fatalf("callback returned %d %q, want success redirect", response.StatusCode, response.Header.Get("Location"))
		}
		response, err := trig.client.Get(trig.cloud.URL + "/ui/api/me")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"UserID":"alex"`) {
			t.Fatalf("authenticated /me returned %d %s", response.StatusCode, body)
		}
		response, err = trig.client.Get(trig.cloud.URL + "/ui/api/logout")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		response, err = trig.client.Get(trig.cloud.URL + "/ui/api/me")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("post-logout /me returned %d, want 401", response.StatusCode)
		}
	})

	t.Run("invalid state", func(t *testing.T) {
		trig := newOIDCTestRig(t, "alex", "")
		defer trig.close()
		_, authURL := trig.begin(t)
		callbackURL := *authURL
		callbackURL.Path = "/ui/api/oidc/callback"
		callbackURL.RawQuery = "state=wrong&code=authorization-code"
		response, err := trig.client.Get(trig.cloud.URL + callbackURL.RequestURI())
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("invalid state returned %d, want 403", response.StatusCode)
		}
	})

	for _, tc := range []struct {
		name string
		mode string
		want int
	}{
		{name: "invalid nonce", mode: "nonce", want: http.StatusForbidden},
		{name: "invalid signature", mode: "signature", want: http.StatusUnauthorized},
		{name: "unknown user", mode: "", want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			username := "alex"
			if tc.name == "unknown user" {
				username = "unknown"
			}
			trig := newOIDCTestRig(t, username, tc.mode)
			defer trig.close()
			_, authURL := trig.begin(t)
			response := trig.callback(t, authURL)
			response.Body.Close()
			if response.StatusCode != tc.want {
				t.Fatalf("%s returned %d, want %d", tc.name, response.StatusCode, tc.want)
			}
		})
	}

	t.Run("invalid PKCE", func(t *testing.T) {
		trig := newOIDCTestRig(t, "alex", "")
		defer trig.close()
		_, authURL := trig.begin(t)
		cloudURL, err := url.Parse(trig.cloud.URL)
		if err != nil {
			t.Fatal(err)
		}
		trig.client.Jar.SetCookies(cloudURL, []*http.Cookie{{Name: oidcVerifierCookie, Value: "wrong", Path: "/", Secure: true}})
		response := trig.callback(t, authURL)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("invalid PKCE returned %d, want 401", response.StatusCode)
		}
	})

	t.Run("no session", func(t *testing.T) {
		trig := newOIDCTestRig(t, "alex", "")
		defer trig.close()
		response, err := trig.client.Get(trig.cloud.URL + "/ui/api/me")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated /me returned %d, want 401", response.StatusCode)
		}
	})
}

func TestOIDCDiscoveryRejectsNonHTTPSEndpoints(t *testing.T) {
	provider := newFakeOIDCProvider(t, "alex", "")
	defer provider.server.Close()
	// A TLS discovery document that advertises an insecure endpoint must never
	// be cached or used for token exchange.
	metadataProvider := provider
	provider.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 metadataProvider.server.URL,
				"authorization_endpoint": "http://idp.invalid/authorize",
				"token_endpoint":         metadataProvider.server.URL + "/token",
				"jwks_uri":               metadataProvider.server.URL + "/jwks",
			})
			return
		}
		metadataProvider.handle(w, r)
	})
	app := testUIApp(&config.Config{OIDC: config.OIDCConfig{
		ProviderURL:  provider.server.URL,
		ClientID:     "rmfakecloud",
		ClientSecret: "secret",
		RedirectURL:  "https://cloud.example.test/ui/api/oidc/callback",
	}}, newFakeUserStorer())
	app.oidcHTTPClient = provider.server.Client()
	router := routerForUIApp(t, app)
	response := requestUI(t, router, http.MethodGet, "/ui/api/oidc/login", nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP discovery endpoint returned %d, want 503", response.Code)
	}
}
