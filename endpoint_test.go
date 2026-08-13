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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestAuthenticateRejectsSteeredEndpoints covers the case where a placeholder
// in the endpoint is filled from the request being authenticated. A client
// which can influence that value must not be able to point the check at a
// different path or host: services commonly expose an unauthenticated
// endpoint which answers 2xx, and reaching it would authenticate everyone.
func TestAuthenticateRejectsSteeredEndpoints(t *testing.T) {
	// stands in for an unauthenticated endpoint on the same service whose
	// reply happens to look like a successful authorization
	open := newAuthService(t, http.StatusOK, `{"manage": true}`)

	for _, tc := range []struct {
		name   string
		tenant string
	}{
		{"traversal out of the configured path", "../health?"},
		{"traversal hidden behind a fragment", "../health#"},
		{"traversal from a deeper segment", "x/../../health?"},
		{"an absolute URL to another host", "http://example.com/health?"},

		// The separators here are percent-encoded, so on the wire this stays
		// one path segment and reads as harmless. A server which decodes
		// before routing sees /../../health and serves whatever is there,
		// which is why the decoded form of the path has to be checked too.
		{"traversal with encoded separators", "..%2F..%2Fhealth"},
		{"traversal with lowercase encoded separators", "..%2f..%2fhealth"},
		{"traversal fully encoded", "%2E%2E%2F%2E%2E%2Fhealth"},
		{"encoded traversal from a deeper segment", "x%2F..%2F..%2Fhealth"},
		{"an encoded separator adds a segment on its own", "a%2Fb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := authenticate(t, Provider{
				Endpoint: open.URL + "/tenants/{http.request.header.X-Tenant}/permissions",
				Claims:   map[string]string{"can_manage": "/manage"},
			}, http.Header{"X-Tenant": []string{tc.tenant}})

			if got.authed {
				t.Fatalf("a tenant of %q steered the check and was authenticated; "+
					"the expanded endpoint must be refused", tc.tenant)
			}
			if got.err == nil {
				t.Error("want an error, so that a steered endpoint is logged rather than " +
					"passing silently as an ordinary denial")
			}
		})
	}
}

// TestValidateEndpoint documents which endpoints are refused at startup,
// before any request is served.
func TestValidateEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		wantErr  bool
		// wantErrText pins the diagnostic, not just the refusal. A placeholder
		// host is also rejected by url.Parse, so asserting only that some
		// error came back would pass even if the operator were left with a
		// syntax error that says nothing about why the host must be fixed.
		wantErrText string
	}{
		{name: "a fixed host", endpoint: "http://auth:9091/verify"},
		{name: "https", endpoint: "https://auth.example.com/verify"},
		{name: "a placeholder in the path is fine", endpoint: "http://auth/tenants/{http.request.header.X-Tenant}/perms"},
		{name: "a placeholder in the query is fine", endpoint: "http://auth/verify?t={http.request.header.X-Tenant}"},

		{name: "empty", endpoint: "", wantErr: true, wantErrText: "endpoint is required"},
		{name: "no host", endpoint: "/verify", wantErr: true, wantErrText: "has no host"},
		{name: "a scheme which is not http", endpoint: "ftp://auth/verify", wantErr: true, wantErrText: "must use http or https"},
		{name: "a traversal in the configured path", endpoint: "http://auth/../verify", wantErr: true, wantErrText: "'..' path segment"},

		// A client which can influence this placeholder would get to name the
		// server that decides whether it is authorized, and could point it at
		// one which always answers yes.
		{
			name:        "a placeholder as the whole host",
			endpoint:    "http://{http.request.header.X-Backend}/verify",
			wantErr:     true,
			wantErrText: "host must not contain a placeholder",
		},
		{
			name:        "a placeholder inside the host",
			endpoint:    "http://{http.request.header.X-Tenant}.auth.example.com/verify",
			wantErr:     true,
			wantErrText: "host must not contain a placeholder",
		},
		{
			name:        "a placeholder as the port",
			endpoint:    "http://auth:{http.request.header.X-Port}/verify",
			wantErr:     true,
			wantErrText: "host must not contain a placeholder",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Provider{Endpoint: tc.endpoint}.validateEndpoint()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateEndpoint(%q) = %v, want error: %v", tc.endpoint, err, tc.wantErr)
			}
			if tc.wantErrText != "" && !strings.Contains(err.Error(), tc.wantErrText) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErrText)
			}
		})
	}
}

// TestPlaceholderHostLeavesNoShapeToCheck is the reason a placeholder host has
// to be refused at startup rather than tolerated. url.Parse cannot read such
// an endpoint, so recordEndpointShape records nothing, and every comparison in
// resolveEndpoint is then skipped: the expanded URL would be accepted whatever
// host it named.
func TestPlaceholderHostLeavesNoShapeToCheck(t *testing.T) {
	p := &Provider{Endpoint: "http://{http.request.header.X-Backend}/verify"}
	p.recordEndpointShape()

	if p.fixedHost != "" || p.pathSegments != 0 {
		t.Fatalf("shape was recorded (host %q, %d segments); this test is no longer describing the risk",
			p.fixedHost, p.pathSegments)
	}
	if err := p.validateEndpoint(); err == nil {
		t.Fatal("an endpoint whose shape cannot be recorded must be refused at startup, " +
			"or resolveEndpoint has nothing left to enforce")
	}
}

// TestResolveEndpoint documents which expansions are accepted, since the
// check has to leave ordinary placeholder use working.
func TestResolveEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		header   string
		want     string
		wantErr  bool
	}{
		{
			name:     "a plain segment is substituted",
			endpoint: "http://auth/tenants/{http.request.header.X-Tenant}/permissions",
			header:   "acme",
			want:     "http://auth/tenants/acme/permissions",
		},
		{
			name:     "a missing placeholder leaves an empty segment, not an error",
			endpoint: "http://auth/tenants/{http.request.header.X-Tenant}/permissions",
			header:   "",
			want:     "http://auth/tenants//permissions",
		},
		{
			name:     "a dotted segment is not a traversal",
			endpoint: "http://auth/tenants/{http.request.header.X-Tenant}/permissions",
			header:   "acme.example",
			want:     "http://auth/tenants/acme.example/permissions",
		},
		{
			name:     "traversal is refused",
			endpoint: "http://auth/tenants/{http.request.header.X-Tenant}/permissions",
			header:   "../health?",
			wantErr:  true,
		},
		{
			name:     "moving to another host is refused",
			endpoint: "http://auth/tenants/{http.request.header.X-Tenant}",
			header:   "",
			want:     "http://auth/tenants/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/protected", nil)
			r.Header.Set("X-Tenant", tc.header)
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, make(map[string]any)))
			repl := caddyhttp.NewTestReplacer(r)

			p := Provider{Endpoint: tc.endpoint}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			t.Cleanup(cancel)
			if err := p.Provision(ctx); err != nil {
				t.Fatalf("provisioning: %v", err)
			}

			got, err := p.resolveEndpoint(repl)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error: %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
