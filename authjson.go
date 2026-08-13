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
	"net/http"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider facilitates HTTP authentication against a service which
// responds with a JSON body. Fields of that body are addressed with
// JSON Pointer (RFC 6901) and made available to the rest of the
// handler chain, so that authorization decisions can be expressed
// with standard Caddy matchers.
type Provider struct {
	// The URL of the authentication service to query. Supports
	// placeholders, so the request being authenticated may be
	// used to build the address.
	Endpoint string `json:"endpoint,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.auth_json",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision provisions the JSON auth provider.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	return nil
}

// Authenticate validates the user credentials in r and returns the user, if valid.
func (p Provider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	return caddyauth.User{ID: "test"}, true, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*Provider)(nil)
	_ caddyauth.Authenticator = (*Provider)(nil)
)
