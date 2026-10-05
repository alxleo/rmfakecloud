package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	oidcStateCookie    = "oidc_state"
	oidcNonceCookie    = "oidc_nonce"
	oidcVerifierCookie = "oidc_pkce_verifier"
	oidcCookieMaxAge   = 300
	oidcRequestTimeout = 10 * time.Second
	// oidcSuccessPath is the frontend route the callback redirects to on success.
	// The frontend must register a matching <Route path="/oidc-success"> to handle it.
	oidcSuccessPath = "/oidc-success"
)

var (
	errNoUserID               = errors.New("no userid available: configured claim not found or empty")
	errInvalidUserID          = errors.New("invalid userid claim")
	errEmailNotVerified       = errors.New("email not verified")
	errOIDCRegistrationClosed = errors.New("OIDC registration closed")
)

var oidcIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+%-]*$`)

type oidcDiscoveryMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcUserIdentity struct {
	Value     string
	ClaimName string
}

func newOIDCUserIdentity(value, claimName string) oidcUserIdentity {
	return oidcUserIdentity{Value: value, ClaimName: claimName}
}

func (identity oidcUserIdentity) usesEmail() bool {
	return identity.ClaimName == "email"
}

func requireOIDCHTTPSURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("oidc %s must be an https URL", field)
	}
	return nil
}

func validateOIDCDiscovery(provider *gooidc.Provider, issuer string) error {
	if err := requireOIDCHTTPSURL(issuer, "issuer"); err != nil {
		return err
	}
	var metadata oidcDiscoveryMetadata
	if err := provider.Claims(&metadata); err != nil {
		return errors.New("oidc discovery metadata unavailable")
	}
	if metadata.Issuer != issuer {
		return errors.New("oidc discovery issuer mismatch")
	}
	for field, endpoint := range map[string]string{
		"authorization endpoint": metadata.AuthorizationEndpoint,
		"token endpoint":         metadata.TokenEndpoint,
		"jwks endpoint":          metadata.JWKSURI,
	} {
		if err := requireOIDCHTTPSURL(endpoint, field); err != nil {
			return err
		}
	}
	return nil
}

func (app *ReactAppWrapper) oidcHTTPClientForRequest() *http.Client {
	app.oidcMu.RLock()
	client := app.oidcHTTPClient
	app.oidcMu.RUnlock()
	if client == nil {
		client = &http.Client{Timeout: oidcRequestTimeout}
	}
	copy := *client
	previousRedirect := copy.CheckRedirect
	copy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("oidc redirect must use https")
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		return nil
	}
	return &copy
}

// ensureOIDCProvider discovers the provider on the first OIDC request. Discovery
// is deliberately outside New so an IdP outage cannot prevent native APIs from
// starting. Both discovery and subsequent token/JWKS calls use the bounded client.
func (app *ReactAppWrapper) ensureOIDCProvider(ctx context.Context) (*gooidc.Provider, oauth2.Config, error) {
	if !app.cfg.OIDC.Enabled() {
		return nil, oauth2.Config{}, errors.New("oidc is not configured")
	}

	app.oidcMu.RLock()
	provider := app.oidcProvider
	config := app.oauth2Config
	app.oidcMu.RUnlock()
	if provider != nil {
		return provider, config, nil
	}

	client := app.oidcHTTPClientForRequest()
	app.oidcMu.Lock()
	defer app.oidcMu.Unlock()
	if app.oidcProvider != nil {
		return app.oidcProvider, app.oauth2Config, nil
	}
	if err := requireOIDCHTTPSURL(app.cfg.OIDC.ProviderURL, "issuer"); err != nil {
		return nil, oauth2.Config{}, errors.New("oidc provider discovery rejected")
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	discoveryCtx = gooidc.ClientContext(discoveryCtx, client)
	discovered, err := gooidc.NewProvider(discoveryCtx, app.cfg.OIDC.ProviderURL)
	if err != nil {
		return nil, oauth2.Config{}, errors.New("oidc provider discovery failed")
	}
	if err := validateOIDCDiscovery(discovered, app.cfg.OIDC.ProviderURL); err != nil {
		return nil, oauth2.Config{}, errors.New("oidc provider discovery rejected")
	}

	app.oidcProvider = discovered
	app.oauth2Config = oauth2.Config{
		ClientID:     app.cfg.OIDC.ClientID,
		ClientSecret: app.cfg.OIDC.ClientSecret,
		RedirectURL:  app.cfg.OIDC.RedirectURL,
		Endpoint:     discovered.Endpoint(),
		Scopes:       app.cfg.OIDC.Scopes(),
	}
	return app.oidcProvider, app.oauth2Config, nil
}

func validateOIDCIdentityValue(value string) error {
	if value == "" || strings.TrimSpace(value) != value || value == "." || value == ".." || !oidcIdentityPattern.MatchString(value) {
		return errInvalidUserID
	}
	return nil
}

// oidcClaims holds the standard OIDC claims read from the ID token.
// The configurable userid and admin claims may be arbitrary dotted paths;
// those still require the raw map passed to extractClaimPath.
type oidcClaims struct {
	Nonce             string `json:"nonce"`
	Email             string `json:"email"`
	EmailVerified     any    `json:"email_verified"` // bool or string "true"/"false" depending on provider
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`
}

// randomURLSafeString generates a cryptographically random base64url-encoded string from n bytes.
func randomURLSafeString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setOIDCCookie writes a short-lived SameSite=Lax cookie for OIDC flow state.
// Lax is required so the cookie survives the cross-site top-level redirect back from the IdP.
func (app *ReactAppWrapper) setOIDCCookie(c *gin.Context, name, value string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, value, oidcCookieMaxAge, "/", "", app.cfg.HTTPSCookie, true)
}

// clearOIDCCookie removes an OIDC flow cookie using the same attributes.
func (app *ReactAppWrapper) clearOIDCCookie(c *gin.Context, name string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, "", -1, "/", "", app.cfg.HTTPSCookie, true)
}

// extractClaimPath traverses a dotted path (e.g. "realm_access.roles") in a raw claims map.
func extractClaimPath(raw map[string]any, path string) (any, bool) {
	parts := strings.SplitN(path, ".", 2)
	val, ok := raw[parts[0]]
	if !ok {
		return nil, false
	}
	if len(parts) == 1 {
		return val, true
	}
	nested, ok := val.(map[string]any)
	if !ok {
		return nil, false
	}
	return extractClaimPath(nested, parts[1])
}

// claimHasValue checks if a claim value (string, []any, or []string) contains expected.
func claimHasValue(value any, expected string) bool {
	switch v := value.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
	}
	return false
}

// claimIsTrue interprets an OIDC boolean claim that may arrive as a bool or as a
// string ("true"/"false"), as allowed by different providers.
func claimIsTrue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

// oidcBegin starts the OIDC authorization code flow with PKCE, state, and nonce.
func (app *ReactAppWrapper) oidcBegin(c *gin.Context) {
	_, oauthConfig, err := app.ensureOIDCProvider(c.Request.Context())
	if err != nil {
		log.Warn("[oidc] provider unavailable during login")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "identity provider unavailable"})
		return
	}
	state, err := randomURLSafeString(32)
	if err != nil {
		log.Error("[oidc] failed to generate state")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLSafeString(32)
	if err != nil {
		log.Error("[oidc] failed to generate nonce")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	pkceVerifier, err := randomURLSafeString(32)
	if err != nil {
		log.Error("[oidc] failed to generate PKCE verifier")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	app.setOIDCCookie(c, oidcStateCookie, state)
	app.setOIDCCookie(c, oidcNonceCookie, nonce)
	app.setOIDCCookie(c, oidcVerifierCookie, pkceVerifier)

	authURL := oauthConfig.AuthCodeURL(
		state,
		gooidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
	c.Redirect(http.StatusFound, authURL)
}

// exchangeAndVerifyToken exchanges the authorization code for tokens and returns verified claims.
// Returns the raw claims map (for configurable dotted-path lookups), a typed oidcClaims
// struct (for standard fields), and true on success; false on error (caller already got an HTTP response).
func (app *ReactAppWrapper) exchangeAndVerifyToken(c *gin.Context, ctx context.Context, code, pkceVerifier string) (map[string]any, oidcClaims, bool) {
	provider, oauthConfig, err := app.ensureOIDCProvider(ctx)
	if err != nil {
		log.Warn("[oidc] provider unavailable during callback")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "identity provider unavailable"})
		return nil, oidcClaims{}, false
	}
	requestCtx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	requestCtx = gooidc.ClientContext(requestCtx, app.oidcHTTPClientForRequest())

	// Exchange authorization code for tokens, presenting the PKCE verifier
	oauth2Token, err := oauthConfig.Exchange(requestCtx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		log.Warn("[oidc] token exchange failed")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token exchange failed"})
		return nil, oidcClaims{}, false
	}

	// Extract raw ID token string
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing id_token in provider response"})
		return nil, oidcClaims{}, false
	}

	// Verify ID token signature, expiry, issuer, and audience
	idTokenVerifier := provider.VerifierContext(requestCtx, &gooidc.Config{ClientID: app.cfg.OIDC.ClientID})
	idToken, err := idTokenVerifier.Verify(requestCtx, rawIDToken)
	if err != nil {
		log.Warn("[oidc] ID token verification failed")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "ID token verification failed"})
		return nil, oidcClaims{}, false
	}

	// Deserialize into typed struct for standard fields
	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		log.Error("[oidc] failed to extract typed claims")
		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, oidcClaims{}, false
	}
	claims.Nonce = idToken.Nonce

	// Deserialize into raw map for configurable dotted-path claim lookups
	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		log.Error("[oidc] failed to extract raw claims")
		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, oidcClaims{}, false
	}

	return rawClaims, claims, true
}

// resolveOIDCIdentity extracts and validates the user identity from the configured
// claim. The claim is authoritative: falling back to email would let a provider
// silently map a missing identity claim onto another local account.
func (app *ReactAppWrapper) resolveOIDCIdentity(rawClaims map[string]any, claims oidcClaims) (oidcUserIdentity, error) {
	userIDClaimName := app.cfg.OIDC.UserIDClaim
	if userIDClaimName == "" {
		userIDClaimName = "preferred_username"
	}

	// Try to extract the configured claim (may be a dotted path like "realm_access.roles")
	if claimVal, ok := extractClaimPath(rawClaims, userIDClaimName); ok {
		if strVal, ok := claimVal.(string); ok {
			identity := newOIDCUserIdentity(strVal, userIDClaimName)
			if err := validateOIDCIdentityValue(strVal); err != nil {
				return identity, err
			}
			return identity, app.validateEmailIdentity(identity, claims)
		}
	}

	return oidcUserIdentity{ClaimName: userIDClaimName}, errNoUserID
}

// validateEmailIdentity enforces email verification for email-based identities.
// Without this, a provider that lets users set an arbitrary unverified email
// could be used to provision or take over an account for another address.
func (app *ReactAppWrapper) validateEmailIdentity(identity oidcUserIdentity, claims oidcClaims) error {
	if identity.usesEmail() && !app.cfg.OIDC.AllowUnverifiedEmail && !claimIsTrue(claims.EmailVerified) {
		return errEmailNotVerified
	}
	return nil
}

// evaluateOIDCAdminStatus returns a *bool reflecting the result of the configured
// admin claim check. nil means the admin claim is not configured; a non-nil pointer
// holds the evaluated value. Callers must not touch a user's admin flag when nil.
func (app *ReactAppWrapper) evaluateOIDCAdminStatus(rawClaims map[string]any) *bool {
	if app.cfg.OIDC.AdminClaim == "" || app.cfg.OIDC.AdminClaimValue == "" {
		return nil
	}
	isAdmin := false
	if claimVal, ok := extractClaimPath(rawClaims, app.cfg.OIDC.AdminClaim); ok {
		isAdmin = claimHasValue(claimVal, app.cfg.OIDC.AdminClaimValue)
	}
	return &isAdmin
}

// provisionNewUser creates and registers a new OIDC-provisioned user.
func (app *ReactAppWrapper) provisionNewUser(userKey string, claims oidcClaims, isAdmin bool) (*model.User, error) {
	randomPassword, err := model.GenPassword()
	if err != nil {
		log.Error("[oidc] failed to generate password for provisioning")
		return nil, err
	}

	user, err := model.NewUser(userKey, randomPassword)
	if err != nil {
		log.Error("[oidc] failed to build user")
		return nil, err
	}
	// NewUser keeps the legacy native sanitizer. Override its identifier with
	// the OIDC key used for lookup so provisioning and filesystem paths agree,
	// including provider usernames containing a hyphen.
	user.ID = userKey
	user.Email = userKey
	if email := claims.Email; email != "" {
		user.Email = email
		user.EmailVerified = claimIsTrue(claims.EmailVerified)
	}

	// Populate user profile from OIDC claims
	if claims.Name != "" {
		user.Name = claims.Name
	}
	if claims.GivenName != "" {
		user.GivenName = claims.GivenName
	}
	if claims.FamilyName != "" {
		user.FamilyName = claims.FamilyName
	}
	if claims.PreferredUsername != "" {
		user.Nickname = claims.PreferredUsername
	}

	user.IsAdmin = isAdmin

	if err := app.userStorer.RegisterUser(user); err != nil {
		log.Error("[oidc] failed to register provisioned user")
		return nil, err
	}

	return user, nil
}

// getOrProvisionUser looks up or auto-provisions an OIDC user.
// adminStatus is nil when no admin claim is configured; in that case the existing
// user's admin flag is left untouched. A non-nil pointer carries the evaluated result.
func (app *ReactAppWrapper) getOrProvisionUser(userKey string, identity oidcUserIdentity, claims oidcClaims, adminStatus *bool) (*model.User, error) {
	isAdmin := adminStatus != nil && *adminStatus
	user, err := app.userStorer.GetUser(userKey)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Error("[oidc] storage error looking up user")
			return nil, err
		}
		if !app.cfg.RegistrationOpen {
			log.Warn("[oidc] refused to provision while registration is closed")
			return nil, errOIDCRegistrationClosed
		}
		// User not found — provision new user
		var newUser *model.User
		newUser, err = app.provisionNewUser(userKey, claims, isAdmin)
		if err != nil {
			return nil, err
		}
		log.Info("[oidc] provisioned new user")
		return newUser, nil
	}

	// Existing user — only re-evaluate admin when an admin claim is configured,
	// otherwise an OIDC login would silently strip admin from an existing user.
	if adminStatus != nil && user.IsAdmin != *adminStatus {
		user.IsAdmin = *adminStatus
		if err := app.userStorer.UpdateUser(user); err != nil {
			log.Error("[oidc] failed to update user admin status")
			return nil, err
		}
		log.Info("[oidc] updated admin status")
	}

	return user, nil
}

// completeOIDCLogin resolves the user identity from verified claims, gets or provisions
// the account, issues a session cookie, and redirects to the success page.
// It handles all identity/provisioning concerns after the protocol-level checks in oidcCallback.
func (app *ReactAppWrapper) completeOIDCLogin(c *gin.Context, rawClaims map[string]any, claims oidcClaims) {
	// Extract, validate and normalise the user identity from claims
	identity, err := app.resolveOIDCIdentity(rawClaims, claims)
	if err != nil {
		switch {
		case errors.Is(err, errNoUserID):
			log.Warn("[oidc] configured userid claim not found or empty")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "userid claim not found or empty"})
		case errors.Is(err, errInvalidUserID):
			log.Warn("[oidc] configured userid claim is not a safe user identifier")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "userid claim is not a safe user identifier"})
		case errors.Is(err, errEmailNotVerified):
			log.Warn("[oidc] rejected login: email not verified")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "email not verified"})
		default:
			log.Error("[oidc] could not resolve provider identity")
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		return
	}

	// The identity is already validated without rewriting it; use the exact
	// provider value for lookup and provisioning so distinct identities cannot
	// collapse onto the same local account.
	userKey := identity.Value

	// Determine admin solely from the configured role claim; re-evaluated on every login
	adminStatus := app.evaluateOIDCAdminStatus(rawClaims)

	// Get or provision user (lookup existing, or create new)
	user, err := app.getOrProvisionUser(userKey, identity, claims, adminStatus)
	if err != nil {
		if errors.Is(err, errOIDCRegistrationClosed) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "registration closed"})
			return
		}
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Issue session and redirect to success page
	if _, err := app.issueWebSession(c, user); err != nil {
		log.Error("[oidc] failed to issue session")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Redirect(http.StatusFound, oidcSuccessPath)
}

// oidcCallback handles the redirect back from the OIDC provider.
// It validates the protocol-level cookies (state, nonce, PKCE), exchanges the
// authorization code, then delegates identity and provisioning to completeOIDCLogin.
func (app *ReactAppWrapper) oidcCallback(c *gin.Context) {
	ctx := c.Request.Context()

	// Provider-side error — sanitize before returning to client
	if errParam := c.Query("error"); errParam != "" {
		log.Warn("[oidc] provider returned an authentication error")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed at identity provider"})
		return
	}

	// Validate state cookie
	stateCookie, err := c.Cookie(oidcStateCookie)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing state cookie"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(stateCookie), []byte(c.Query("state"))) != 1 {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "authentication failed"})
		return
	}

	// Read nonce and PKCE verifier before clearing any cookies
	nonceCookie, err := c.Cookie(oidcNonceCookie)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing nonce cookie"})
		return
	}
	pkceVerifier, err := c.Cookie(oidcVerifierCookie)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing pkce verifier cookie"})
		return
	}

	// Clear all OIDC flow cookies before any external calls
	app.clearOIDCCookie(c, oidcStateCookie)
	app.clearOIDCCookie(c, oidcNonceCookie)
	app.clearOIDCCookie(c, oidcVerifierCookie)

	// Exchange authorization code for tokens and verify claims
	rawClaims, claims, ok := app.exchangeAndVerifyToken(c, ctx, c.Query("code"), pkceVerifier)
	if !ok {
		return // Error already written to response
	}

	// Verify nonce with constant-time comparison
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonceCookie)) != 1 {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "authentication failed"})
		return
	}

	app.completeOIDCLogin(c, rawClaims, claims)
}

type publicAuthConfig struct {
	OIDCEnabled       bool   `json:"oidc_enabled"`
	OIDCLoginURL      string `json:"oidc_login_url,omitempty"`
	OIDCDisplayName   string `json:"oidc_display_name,omitempty"`
	LocalLoginEnabled bool   `json:"local_login_enabled"`
}

// authConfigHandler exposes only the public choices needed to render the login
// page. Client secrets and provider metadata stay server-side.
func (app *ReactAppWrapper) authConfigHandler(c *gin.Context) {
	response := publicAuthConfig{
		OIDCEnabled:       app.cfg.OIDC.Enabled(),
		LocalLoginEnabled: app.cfg.OIDC.LocalLoginEnabled(),
	}
	if response.OIDCEnabled {
		response.OIDCLoginURL = "/ui/api/oidc/login"
		response.OIDCDisplayName = app.cfg.OIDC.LoginDisplayName()
	}
	c.JSON(http.StatusOK, response)
}

// meHandler returns the current authenticated user's profile as JSON.
// Used by the frontend after an OIDC redirect to hydrate localStorage.
func (app *ReactAppWrapper) meHandler(c *gin.Context) {
	uid := userID(c)
	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error("[me] user not found: ", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	scopes := ""
	if user.Sync15 {
		scopes = isSync15Key
	}
	roles := []string{"User"}
	if user.IsAdmin {
		roles = []string{AdminRole}
	}
	c.JSON(http.StatusOK, gin.H{
		"UserID": user.ID,
		"Email":  user.Email,
		"Scopes": scopes,
		"Roles":  roles,
	})
}
