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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("auth_json", parseCaddyfile)

	// Directives from plugins have no place in Caddy's default ordering,
	// so one must be declared or users are forced to wrap every use of
	// auth_json in a route block. It is ordered alongside the other
	// authentication directives, before the request reaches any handler
	// which would act on an unauthenticated request.
	httpcaddyfile.RegisterDirectiveOrder("auth_json", httpcaddyfile.Before, "forward_auth")
}

// UnmarshalCaddyfile sets up the provider from Caddyfile tokens. Syntax:
//
//	auth_json [<matcher>] {
//	    endpoint <url>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "endpoint":
			if p.Endpoint != "" {
				return d.Errf("endpoint already declared: %s", p.Endpoint)
			}
			if !d.AllArgs(&p.Endpoint) {
				return d.ArgErr()
			}
		case "method":
			if p.Method != "" {
				return d.Errf("method already declared: %s", p.Method)
			}
			if !d.AllArgs(&p.Method) {
				return d.ArgErr()
			}

		case "forward_headers":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			p.ForwardHeaders = append(p.ForwardHeaders, args...)

		case "timeout":
			if p.Timeout != 0 {
				return d.Errf("timeout already declared")
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad duration value %s: %v", d.Val(), err)
			}
			p.Timeout = caddy.Duration(dur)

		default:
			return d.Errf("unrecognized auth_json subdirective '%s'", d.Val())
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Provider, wrapped in
// an authentication handler. The provider is keyed by the last segment of
// its module ID, which is how Caddy resolves it within the
// http.authentication.providers namespace.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p Provider
	if err := p.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"auth_json": caddyconfig.JSON(p, nil),
		},
	}, nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Provider)(nil)
