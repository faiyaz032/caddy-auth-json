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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule(Provider{})
}

const (
	defaultTimeout = 10 * time.Second
	defaultMaxSize = 1 << 20 // 1 MB
)

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

	// Fields to extract from the authentication service's response body.
	// Each key is a variable name, made available as {vars.<name>} and
	// as {http.auth.user.<name>}; each value is a JSON Pointer into the
	// response body. A field which the service omits is simply not set.
	Claims map[string]string `json:"claims,omitempty"`

	// A JSON Pointer to the field which identifies the user, exposed
	// as {http.auth.user.id}.
	UserID string `json:"user_id,omitempty"`

	// The maximum amount of the authentication service's response body
	// to read. A larger response is rejected rather than truncated,
	// since a partial JSON document cannot be trusted. Default: 1MB
	MaxSize int64 `json:"max_size,omitempty"`

	// the shape the configured endpoint had before any placeholder was
	// expanded; recorded in Provision and enforced on every request.
	// See endpoint.go.
	fixedScheme  string
	fixedHost    string
	pathSegments int

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
		p.Timeout = caddy.Duration(defaultTimeout)
	}

	if p.MaxSize == 0 {
		p.MaxSize = defaultMaxSize
	}

	p.recordEndpointShape()

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

// Cleanup releases the connections held open for the authentication service.
// Caddy provisions a fresh instance on every config reload, so without this
// the previous client's idle connections would linger until the garbage
// collector got to them.
func (p *Provider) Cleanup() error {
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
	return nil
}

// Validate ensures the provider's configuration is valid. Pointers are
// checked here rather than at first use, so that a malformed one is
// reported at startup instead of silently denying every request.
func (p *Provider) Validate() error {
	if err := p.validateEndpoint(); err != nil {
		return err
	}

	if p.MaxSize < 0 {
		return fmt.Errorf("max_size must not be negative")
	}
	if p.UserID != "" {
		if err := validateJSONPointer(p.UserID); err != nil {
			return fmt.Errorf("user_id: %w", err)
		}
	}
	for name, ptr := range p.Claims {
		if err := validateJSONPointer(ptr); err != nil {
			return fmt.Errorf("claim %s: %w", name, err)
		}
	}
	return nil
}

// Authenticate validates the user credentials in r and returns the user, if valid.
func (p Provider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	endpoint, err := p.resolveEndpoint(repl)
	if err != nil {
		return caddyauth.User{}, false, err
	}

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

	// One byte past the cap is read so that a body sitting exactly on the
	// limit can be told apart from one which ran over it. Reading here
	// rather than after the status check also drains the response, which
	// lets the connection go back to the pool.
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.MaxSize+1))
	if err != nil {
		return caddyauth.User{}, false, fmt.Errorf("reading auth response: %w", err)
	}

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

	// The body is rejected rather than truncated: a JSON document cut off
	// partway either fails to parse or, worse, parses as a valid object
	// which happens to be missing the field that would have denied access.
	if int64(len(body)) > p.MaxSize {
		return caddyauth.User{}, false, fmt.Errorf("auth response exceeds max_size of %d bytes", p.MaxSize)
	}

	// With nothing to extract, a 2xx is the whole verdict, and the
	// response need not be JSON at all.
	if len(p.Claims) == 0 && p.UserID == "" {
		return caddyauth.User{}, true, nil
	}

	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return caddyauth.User{}, false, fmt.Errorf("decoding auth response: %w", err)
	}

	var user caddyauth.User

	if p.UserID != "" {
		if val, found := jsonPointerGet(doc, p.UserID); found {
			user.ID = claimToString(val)
		}
	}

	if len(p.Claims) > 0 {
		user.Metadata = make(map[string]string, len(p.Claims))
	}
	for name, ptr := range p.Claims {
		val, found := jsonPointerGet(doc, ptr)
		if !found {
			// a claim the service omitted is left unset, so that
			// {vars.<name>} is empty rather than false
			continue
		}

		// The value keeps the type it decoded as, so that a CEL
		// expression like {vars.can_manage} == true compares against a
		// real boolean. Stringifying here would force users to write
		// == "true" instead.
		caddyhttp.SetVar(r.Context(), name, val)

		// User.Metadata is map[string]string and cannot hold the native
		// value, so a rendered form is stored alongside it.
		user.Metadata[name] = claimToString(val)
	}

	return user, true, nil
}

// claimToString renders a decoded JSON value for User.Metadata, which can
// hold nothing but strings. Numbers are formatted without an exponent so
// that identifiers stay legible, and objects and arrays are re-encoded as
// JSON rather than rendered with Go's native formatting.
func claimToString(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case bool:
		return strconv.FormatBool(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// Interface guards
var (
	_ caddy.Provisioner       = (*Provider)(nil)
	_ caddyauth.Authenticator = (*Provider)(nil)
	_ caddy.Validator         = (*Provider)(nil)
	_ caddy.CleanerUpper      = (*Provider)(nil)
)
