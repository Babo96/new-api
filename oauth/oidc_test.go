package oauth

import (
	"encoding/base64"
	"slices"
	"testing"

	"github.com/QuantumNous/new-api/common"
)

func TestExtractOIDCTokenGroupsPreservesTokenOrderAndDedupes(t *testing.T) {
	token := &OAuthToken{
		IDToken:     makeUnsignedJWT(t, map[string]any{"groups": []string{"id-admin", "shared", ""}}),
		AccessToken: makeUnsignedJWT(t, map[string]any{"groups": []string{"access-user", "shared", "access-extra"}}),
	}

	groups := appendUniqueGroups(extractOIDCTokenGroups(token), "userinfo-group", "id-admin")
	want := []string{"id-admin", "shared", "access-user", "access-extra", "userinfo-group"}

	if !slices.Equal(groups, want) {
		t.Fatalf("groups = %#v, want %#v", groups, want)
	}
}

func TestExtractOIDCTokenGroupsAcceptsStringGroupsClaim(t *testing.T) {
	token := &OAuthToken{
		IDToken:     makeUnsignedJWT(t, map[string]any{"groups": "id-admin"}),
		AccessToken: makeUnsignedJWT(t, map[string]any{"groups": "access-user"}),
	}

	groups := extractOIDCTokenGroups(token)
	want := []string{"id-admin", "access-user"}

	if !slices.Equal(groups, want) {
		t.Fatalf("groups = %#v, want %#v", groups, want)
	}
}

func TestExtractOIDCTokenGroupsIgnoresMalformedAndEmptyTokens(t *testing.T) {
	if groups := extractOIDCGroupsClaim("opaque-token"); len(groups) != 0 {
		t.Fatalf("malformed token groups = %#v, want none", groups)
	}

	if groups := extractOIDCTokenGroups(&OAuthToken{}); len(groups) != 0 {
		t.Fatalf("empty token groups = %#v, want none", groups)
	}

	if groups := extractOIDCTokenGroups(nil); len(groups) != 0 {
		t.Fatalf("nil token groups = %#v, want none", groups)
	}
}

func makeUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	header, err := common.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal JWT header: %v", err)
	}
	payload, err := common.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal JWT claims: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}
