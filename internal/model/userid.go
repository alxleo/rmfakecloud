package model

import (
	"regexp"
	"strings"
)

// userIDDisallowed matches characters that are unsafe or ambiguous in a user
// directory name. This normalizer is for identities supplied by OIDC only;
// the native password path continues to use the legacy sanitizer.
var userIDDisallowed = regexp.MustCompile(`[^a-z0-9.@_-]+`)

// NormalizeUserID returns the canonical key for an OIDC identity: lowercased,
// trimmed, and reduced to characters safe for a user directory. An empty
// result means the provider identity contains no usable name.
func NormalizeUserID(id string) string {
	cleaned := userIDDisallowed.ReplaceAllString(strings.ToLower(strings.TrimSpace(id)), "")
	if strings.Trim(cleaned, ".") == "" {
		return ""
	}
	return cleaned
}
