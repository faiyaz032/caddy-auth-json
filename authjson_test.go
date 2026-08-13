// Copyright 2026 Faiyaz Rahman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authjson

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

// authService stands in for the authentication service the provider queries.
// It records the request it was sent so that tests can assert on what the
// provider actually forwarded.
type authService struct {
	*httptest.Server
	got *http.Request
}

func newAuthService(t *testing.T, status int, body string) *authService {
	t.Helper()
	svc := new(authService)
	svc.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.got = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(svc.Close)
	return svc
}

// result is the full outcome of one authentication, including the variables
// the provider set on the request, which are otherwise invisible to callers.
type result struct {
	user   caddyauth.User
	authed bool
	err    error
	vars   map[string]any
}

// authenticate runs a single request through p, provisioning it first so that
// defaults and the HTTP client are set up exactly as they are in production.
func authenticate(t *testing.T, p Provider, header http.Header) result {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	if err := p.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validating: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if header != nil {
		r.Header = header
	}

	// the server normally installs both of these; without them the provider
	// cannot read placeholders or publish variables
	vars := make(map[string]any)
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
	caddyhttp.NewTestReplacer(r)

	user, authed, err := p.Authenticate(httptest.NewRecorder(), r)
	return result{user: user, authed: authed, err: err, vars: vars}
}

// TestAuthenticate documents the verdict the provider reaches for each kind of
// response an authentication service may give, and what it extracts from it.
func TestAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		name string

		// what the authentication service replies with
		authStatus int
		authBody   string

		// how the provider is configured
		claims  map[string]string
		userID  string
		maxSize int64

		// what should happen
		wantAuthed  bool
		wantErr     bool
		wantUserID  string
		wantVars    map[string]any
		wantNoVars  []string
		wantErrText string
	}{
		{
			name:       "a 2xx grants access",
			authStatus: http.StatusOK,
			authBody:   `{}`,
			wantAuthed: true,
		},
		{
			name:       "a 4xx denies access without reporting an error",
			authStatus: http.StatusForbidden,
			authBody:   `{"error":"denied"}`,
			wantAuthed: false,
			wantErr:    false,
		},
		{
			// the service being broken is still a denial as far as the
			// verdict goes; it is reported as an error only so that it can
			// be logged and told apart from a rejected user
			name:       "an unreachable-looking 5xx is a denial, not an error",
			authStatus: http.StatusInternalServerError,
			authBody:   `oops`,
			wantAuthed: false,
			wantErr:    false,
		},
		{
			// values keep the type they decoded as, which is what lets a CEL
			// expression compare {vars.can_manage} against a real boolean
			// rather than against the string "true"
			name:       "claims keep their decoded JSON types",
			authStatus: http.StatusOK,
			authBody:   `{"manage": true, "seats": 7, "plan": "pro"}`,
			claims: map[string]string{
				"can_manage": "/manage",
				"seats":      "/seats",
				"plan":       "/plan",
			},
			wantAuthed: true,
			wantVars: map[string]any{
				"can_manage": true,
				"seats":      float64(7),
				"plan":       "pro",
			},
		},
		{
			// an omitted claim must stay unset rather than default to false,
			// so that an expression can tell "denied" from "not mentioned"
			name:       "a claim the service omits is left unset",
			authStatus: http.StatusOK,
			authBody:   `{"manage": true}`,
			claims: map[string]string{
				"can_manage": "/manage",
				"can_bill":   "/bill",
			},
			wantAuthed: true,
			wantVars:   map[string]any{"can_manage": true},
			wantNoVars: []string{"can_bill"},
		},
		{
			// this is why fields are addressed with JSON Pointer rather than
			// dot-notation: both keys are legal in one document, and "a.b"
			// alone cannot say which is meant
			name:       "a key containing a dot is distinct from a nested key",
			authStatus: http.StatusOK,
			authBody:   `{"a.b": "dotted", "a": {"b": "nested"}}`,
			claims: map[string]string{
				"dotted": "/a.b",
				"nested": "/a/b",
			},
			wantAuthed: true,
			wantVars: map[string]any{
				"dotted": "dotted",
				"nested": "nested",
			},
		},
		{
			name:       "user_id names the field which identifies the user",
			authStatus: http.StatusOK,
			authBody:   `{"user": {"id": "u-42"}}`,
			userID:     "/user/id",
			wantAuthed: true,
			wantUserID: "u-42",
		},
		{
			// truncating would risk producing a document which still parses
			// but is missing the very field that would have denied access
			name:        "a body over max_size is rejected rather than truncated",
			authStatus:  http.StatusOK,
			authBody:    `{"manage": true, "padding": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
			claims:      map[string]string{"can_manage": "/manage"},
			maxSize:     16,
			wantAuthed:  false,
			wantErr:     true,
			wantErrText: "exceeds max_size",
		},
		{
			name:        "a body which is not JSON is an error when claims are configured",
			authStatus:  http.StatusOK,
			authBody:    `<html>not json</html>`,
			claims:      map[string]string{"can_manage": "/manage"},
			wantAuthed:  false,
			wantErr:     true,
			wantErrText: "decoding auth response",
		},
		{
			// with nothing to extract the provider is a plain status gate,
			// so the service is free to reply with anything at all
			name:       "a body which is not JSON is fine when no claims are configured",
			authStatus: http.StatusOK,
			authBody:   `<html>not json</html>`,
			wantAuthed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newAuthService(t, tc.authStatus, tc.authBody)

			got := authenticate(t, Provider{
				Endpoint: svc.URL,
				Claims:   tc.claims,
				UserID:   tc.userID,
				MaxSize:  tc.maxSize,
			}, nil)

			if got.authed != tc.wantAuthed {
				t.Errorf("authenticated = %v, want %v", got.authed, tc.wantAuthed)
			}
			if (got.err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error: %v", got.err, tc.wantErr)
			}
			if tc.wantErrText != "" && !strings.Contains(got.err.Error(), tc.wantErrText) {
				t.Errorf("error = %q, want it to mention %q", got.err, tc.wantErrText)
			}
			if got.user.ID != tc.wantUserID {
				t.Errorf("user ID = %q, want %q", got.user.ID, tc.wantUserID)
			}
			for name, want := range tc.wantVars {
				if !reflect.DeepEqual(got.vars[name], want) {
					t.Errorf("vars[%q] = %#v, want %#v", name, got.vars[name], want)
				}
			}
			for _, name := range tc.wantNoVars {
				if _, ok := got.vars[name]; ok {
					t.Errorf("vars[%q] was set to %#v, want it left unset", name, got.vars[name])
				}
			}
		})
	}
}

// TestAuthenticateForwardsOnlyListedHeaders shows that forward_headers is an
// allowlist: the authentication service is a separate service, and is sent
// only what it was explicitly promised.
func TestAuthenticateForwardsOnlyListedHeaders(t *testing.T) {
	svc := newAuthService(t, http.StatusOK, `{}`)

	incoming := http.Header{
		"X-Token":  []string{"forwarded"},
		"X-Secret": []string{"withheld"},
		"Cookie":   []string{"a=1", "b=2"},
	}

	authenticate(t, Provider{
		Endpoint:       svc.URL,
		ForwardHeaders: []string{"X-Token", "Cookie"},
	}, incoming)

	if got := svc.got.Header.Get("X-Token"); got != "forwarded" {
		t.Errorf("X-Token = %q, want it forwarded", got)
	}
	if got := svc.got.Header.Get("X-Secret"); got != "" {
		t.Errorf("X-Secret = %q, want it withheld: it is not in forward_headers", got)
	}

	// headers repeat, and every value has to survive the copy; taking only
	// the first would silently drop all but one cookie
	if got := svc.got.Header.Values("Cookie"); !reflect.DeepEqual(got, []string{"a=1", "b=2"}) {
		t.Errorf("Cookie = %#v, want every value forwarded", got)
	}
}

// TestAuthenticateDoesNotFollowRedirects covers the case which would otherwise
// grant access to everyone: a service which answers "not logged in" with a
// redirect to a login page, where that page itself replies 200.
func TestAuthenticateDoesNotFollowRedirects(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "please log in")
	}))
	t.Cleanup(login.Close)

	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, login.URL, http.StatusFound)
	}))
	t.Cleanup(svc.Close)

	got := authenticate(t, Provider{Endpoint: svc.URL}, nil)

	if got.authed {
		t.Fatal("redirect to a login page was treated as success; " +
			"the 302 must be rejected rather than followed to the login page's 200")
	}
	if got.err != nil {
		t.Errorf("error = %v, want a plain denial", got.err)
	}
}

// TestCleanup covers being torn down without ever having been provisioned,
// which happens when an earlier module in the same config fails to load.
func TestCleanup(t *testing.T) {
	t.Run("before provisioning", func(t *testing.T) {
		p := new(Provider)
		if err := p.Cleanup(); err != nil {
			t.Fatalf("Cleanup on an unprovisioned provider: %v", err)
		}
	})

	t.Run("after provisioning", func(t *testing.T) {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		t.Cleanup(cancel)

		p := &Provider{Endpoint: "http://auth.invalid/verify"}
		if err := p.Provision(ctx); err != nil {
			t.Fatalf("provisioning: %v", err)
		}
		if err := p.Cleanup(); err != nil {
			t.Fatalf("Cleanup: %v", err)
		}
	})
}

// TestClaimToString documents how decoded JSON values are rendered for
// User.Metadata, which can carry nothing but strings.
func TestClaimToString(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want string
	}{
		{"string passes through", "u-42", "u-42"},
		{"bool", true, "true"},
		{"whole number has no decimal point", float64(7), "7"},
		{"fractional number", float64(1.5), "1.5"},

		// %v would render this as 1.234567890123e+12 and make identifiers
		// unreadable, so numbers are formatted without an exponent
		{"large number is not written in scientific notation", float64(1234567890123), "1234567890123"},

		{"null becomes empty", nil, ""},
		{"object is re-encoded as JSON", map[string]any{"id": "u-42"}, `{"id":"u-42"}`},
		{"array is re-encoded as JSON", []any{"a", "b"}, `["a","b"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := claimToString(tc.in); got != tc.want {
				t.Errorf("claimToString(%#v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
