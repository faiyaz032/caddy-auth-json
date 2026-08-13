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
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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

	// The HTTP method to use for the authentication request. Default: GET
	Method string `json:"method,omitempty"`

	// Header fields to copy from the incoming request onto the
	// authentication request. Only the fields listed here are sent.
	ForwardHeaders []string `json:"forward_headers,omitempty"`

	// How long to wait for the authentication service to respond.
	// Default: 10s
	Timeout caddy.Duration `json:"timeout,omitempty"`

	client *http.Client
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.auth_json",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision applies defaults and builds the HTTP client which is used
// to reach the authentication service. The client is built once and
// reused, so that connections to the service may be pooled.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()

	if p.Method == "" {
		p.Method = http.MethodGet
	}

	if p.Timeout == 0 {
		p.Timeout = caddy.Duration(10 * time.Second)
	}

	p.client = &http.Client{
		Timeout: time.Duration(p.Timeout),

		// Authentication services commonly answer "not logged in" with
		// a redirect to a login page. Following it would yield that
		// page's 200 and so authenticate every anonymous request, which
		// is why redirects are surfaced as-is and left for the status
		// check in Authenticate to reject.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nil
}

// Validate ensures the provider's configuration is valid.
func (p *Provider) Validate() error {
	if p.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	return nil
}

// Authenticate validates the user credentials in r and returns the user, if valid.
func (p Provider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	endpoint := repl.ReplaceAll(p.Endpoint, "")

	// the incoming request's context is used so that a client
	// disconnect also cancels the authentication request
	req, err := http.NewRequestWithContext(r.Context(), p.Method, endpoint, nil)
	if err != nil {
		return caddyauth.User{}, false, fmt.Errorf("building auth request: %w", err)
	}

	for _, field := range p.ForwardHeaders {
		if values := r.Header.Values(field); len(values) > 0 {
			req.Header[http.CanonicalHeaderKey(field)] = values
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return caddyauth.User{}, false, fmt.Errorf("querying auth service: %w", err)
	}
	defer resp.Body.Close()

	// the body is unused for now, but draining it lets the
	// connection be returned to the pool and reused
	_, _ = io.Copy(io.Discard, resp.Body)

	// A non-2xx response means the service declined the request, which is
	// reported as an unauthenticated result rather than an error. Both
	// outcomes end in 401, but only an error is logged at ERROR level and
	// exposed via the {http.auth.auth_json.error} placeholder, so keeping
	// them distinct is what lets an operator tell "the service is down"
	// apart from "this user was denied".
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if c := p.logger.Check(zapcore.DebugLevel, "authentication denied"); c != nil {
			c.Write(
				zap.String("endpoint", endpoint),
				zap.Int("status", resp.StatusCode),
			)
		}
		return caddyauth.User{}, false, nil
	}

	return caddyauth.User{}, true, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*Provider)(nil)
	_ caddyauth.Authenticator = (*Provider)(nil)
	_ caddy.Validator         = (*Provider)(nil)
)
