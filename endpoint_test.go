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
