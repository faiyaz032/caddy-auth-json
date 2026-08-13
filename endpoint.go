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
	"net/url"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

// The endpoint may contain placeholders, and those placeholders are routinely
// filled from the request being authenticated. That makes the address of the
// authentication request partly attacker-controlled, so the three functions
// here exist to keep an expansion from addressing anything other than what
// was configured.
//
// The attack they prevent: given
//
//	endpoint http://auth/tenants/{http.request.header.X-Tenant}/permissions
//
// a client sending "X-Tenant: ../health?" produces
// http://auth/tenants/../health?/permissions, which resolves to /health.
// Services commonly expose an unauthenticated endpoint like that, and if it
// answers 2xx with a plausible body then every request is authenticated.

// recordEndpointShape captures what the endpoint looked like before any
// placeholder was expanded, so that resolveEndpoint can tell whether an
// expansion changed it. It is called once, from Provision.
func (p *Provider) recordEndpointShape() {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		// a malformed endpoint is reported by resolveEndpoint on the first
		// request; leaving the shape unset simply skips the comparisons
		return
	}

	p.pathSegments = len(strings.Split(u.EscapedPath(), "/"))

	// A host given outright is the only host the authentication request may
	// ever reach. A host which is itself a placeholder cannot be pinned, and
	// is left to the operator's judgement.
	if u.Host != "" && !strings.Contains(u.Host, "{") {
		p.fixedScheme, p.fixedHost = u.Scheme, u.Host
	}
}

// validateEndpoint checks the configured endpoint at startup, before any
// placeholder is involved.
func (p Provider) validateEndpoint() error {
	if p.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}

	// resolveEndpoint treats a traversal segment as proof that a placeholder
	// introduced one, which only holds if the configured endpoint has none.
	if slices.Contains(strings.Split(p.Endpoint, "/"), "..") {
		return fmt.Errorf("endpoint must not contain a '..' path segment")
	}

	return nil
}

// resolveEndpoint expands placeholders in the configured endpoint and checks
// that the result still addresses the service which was configured. It
// returns an error rather than a plain denial so that an attempt to steer the
// authentication request is logged, and reaches the
// {http.auth.auth_json.error} placeholder, instead of looking like an
// ordinary rejected user.
func (p Provider) resolveEndpoint(repl *caddy.Replacer) (string, error) {
	raw := repl.ReplaceAll(p.Endpoint, "")

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("endpoint %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("endpoint %q must use http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("endpoint %q has no host", raw)
	}

	if p.fixedHost != "" && (u.Scheme != p.fixedScheme || u.Host != p.fixedHost) {
		return "", fmt.Errorf("endpoint expanded to %s://%s, but was configured for %s://%s",
			u.Scheme, u.Host, p.fixedScheme, p.fixedHost)
	}

	segments := strings.Split(u.EscapedPath(), "/")

	if slices.Contains(segments, "..") {
		return "", fmt.Errorf("endpoint %q traverses out of its path after placeholder expansion", raw)
	}

	// A placeholder stands for one path segment. A value carrying '/', '?' or
	// '#' would otherwise restructure the URL around it and address a
	// different endpoint without any traversal being involved: a tenant of
	// "http://elsewhere/health?" turns /tenants/{tenant}/permissions into
	// /tenants/http:/elsewhere/health.
	if p.pathSegments != 0 && len(segments) != p.pathSegments {
		return "", fmt.Errorf("endpoint %q has %d path segments after placeholder expansion, but was configured with %d",
			raw, len(segments), p.pathSegments)
	}

	return u.String(), nil
}
