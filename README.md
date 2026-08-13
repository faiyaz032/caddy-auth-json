# caddy-auth-json

A Caddy plugin that asks an HTTP service whether a request is allowed, and reads the answer out of a JSON response body.

## The problem

Caddy's built in `forward_auth` works well when your auth service answers with HTTP headers. It checks the status code, and it can copy headers like `Remote-User` onto the request.

Many services don't work that way. They return a JSON document instead:

```json
{
  "manage": true,
  "read": true,
  "user": { "id": "u-42" }
}
```

Caddy cannot read that body. Response matchers only see the status code and the headers, so there is no way to route on `manage` or pass `user.id` to your backend.

This plugin fills that gap. It calls your auth service, pulls named fields out of the JSON reply, and puts them into Caddy variables. From there you use ordinary Caddy matchers to decide what each user may do.

## Install

```bash
xcaddy build --with github.com/faiyaz032/caddy-auth-json
```

## Quick start

```caddy
example.com {
	auth_json {
		endpoint http://auth-service:9091/verify
		forward_headers Cookie
		claim can_manage /manage
		user_id /user/id
	}

	reverse_proxy app:8080
}
```

What happens on each request:

1. Caddy sends a GET to `http://auth-service:9091/verify`, forwarding the client's `Cookie` header.
2. If the service answers with a status outside the 200 range, Caddy returns 401 and stops.
3. If it answers 2xx, the JSON body is parsed. The value at `/manage` is stored as `{vars.can_manage}`, and the value at `/user/id` becomes `{http.auth.user.id}`.
4. The request continues to your app.

Now you can use those values anywhere in your config:

```caddy
example.com {
	auth_json {
		endpoint http://auth-service:9091/verify
		forward_headers Cookie
		claim can_manage /manage
		user_id /user/id
	}

	# only users with "manage": true may reach the admin area
	@can_manage expression {vars.can_manage} == true

	route {
		handle /admin/* {
			route {
				reverse_proxy @can_manage app:8080
				respond "You do not have permission to manage this." 403
			}
		}
		handle {
			reverse_proxy app:8080 {
				header_up X-User {http.auth.user.id}
			}
		}
	}
}
```

## Addressing fields

Fields are named with a [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901) (RFC 6901), not with dots.

| Pointer | Reads |
| --- | --- |
| `/manage` | the top level `manage` field |
| `/user/id` | `id` inside the `user` object |
| `/roles/0` | the first item of the `roles` array |
| `/a~1b` | the key `a/b` (`~1` means a literal `/`) |
| `/a~0b` | the key `a~b` (`~0` means a literal `~`) |

Dots are avoided on purpose. A JSON key may itself contain a dot, so `{"a.b": 1, "a": {"b": 2}}` is valid JSON with two different values. Dot notation cannot tell them apart. With pointers, `/a.b` and `/a/b` are clearly different.

## If your service returns a different shape

Nothing in this plugin is tied to the field names used above. `claim` and `user_id` take any pointer, so you point them at whatever your service actually returns. Then you pick the expression that matches the JSON type of the value.

**An id called `sub`, with the permission nested**

```json
{ "sub": "u-42", "email": "a@b.c", "permissions": { "manage": true } }
```

```caddy
auth_json {
	endpoint http://auth:9091/verify
	user_id /sub
	claim can_manage /permissions/manage
	claim email      /email
}
```

**Scopes in a single string**

Some services return a list of scopes as one string with spaces in it. Search inside it rather than comparing the whole thing.

```json
{ "active": true, "username": "alice", "scope": "read write admin" }
```

```caddy
auth_json {
	endpoint http://auth:9091/verify
	user_id /username
	claim active /active
	claim scope  /scope
}

@admin expression {vars.active} == true && {vars.scope}.contains("admin")
```

**A list of roles**

An array stays an array, so you can test membership with `in`.

```json
{ "user": "bob", "roles": ["editor", "admin"], "tenant": { "tier": "gold" } }
```

```caddy
auth_json {
	endpoint http://auth:9091/verify
	user_id /user
	claim roles /roles
	claim tier  /tenant/tier
}

@is_admin expression "admin" in {vars.roles}
```

**An array at the top level**

Array positions are addressed with plain numbers.

```json
[{ "resource": "si-1", "allowed": true, "level": 3 }]
```

```caddy
auth_json {
	endpoint http://auth:9091/verify
	claim allowed /0/allowed
	claim level   /0/level
}

@ok expression {vars.allowed} == true && {vars.level} >= 2
```

### Picking the right expression

| Value in the JSON | Write |
| --- | --- |
| `true` or `false` | `{vars.x} == true` |
| a string | `{vars.x} == "gold"` |
| a string holding a list | `{vars.x}.contains("admin")` |
| a number | `{vars.x} >= 2` |
| an array | `"admin" in {vars.x}` |
| the field was missing | `{vars.x} == ""` |

Values keep the type they had in the JSON, so a JSON `true` is a real boolean and a JSON array is a real list. You don't have to compare against strings.

### One shape that will not work

If your service returns a list of objects and you need to find one by its contents, this plugin cannot do it:

```json
{
  "permissions": [
    { "resource": "si-1", "manage": true },
    { "resource": "si-2", "manage": false }
  ]
}
```

A pointer can only name a fixed position, like `/permissions/0/manage`. There is no way to say "the entry where resource is si-1". If the order is not guaranteed, you will read the wrong permission.

Two ways around it:

- Ask the service for one resource at a time, and put the id in the endpoint: `endpoint http://auth:9091/resources/{http.request.uri.path.1}/permissions`.
- Have the service return a flat object keyed by resource, so you can address it directly: `claim can_manage /permissions/si-1/manage`.

## Options

```caddy
auth_json [<matcher>] {
	endpoint        <url>
	method          <verb>
	forward_headers <field...>
	timeout         <duration>
	claim           <name> <pointer>
	user_id         <pointer>
	max_size        <size>
}
```

| Option | Default | Meaning |
| --- | --- | --- |
| `endpoint` | required | URL of the auth service. Placeholders are allowed. |
| `method` | `GET` | HTTP method used for the auth request. |
| `forward_headers` | none | Header fields copied from the incoming request. Nothing else is sent. |
| `timeout` | `10s` | How long to wait for the auth service. |
| `claim` | none | Store the value at `<pointer>` as `{vars.<name>}`. Repeat for each field. |
| `user_id` | none | Which field identifies the user. Becomes `{http.auth.user.id}`. |
| `max_size` | `1MB` | Largest response body accepted. Bigger replies are refused. |

If you set no `claim` and no `user_id`, the plugin only checks the status code. The response does not have to be JSON in that case.

## Placeholders you get

| Placeholder | Contains |
| --- | --- |
| `{vars.<name>}` | The claim value with its original JSON type. A JSON `true` stays a boolean, so `== true` works in expressions. |
| `{http.auth.user.id}` | The value at `user_id`. |
| `{http.auth.user.<name>}` | The same claim as a string. Handy for headers and logs. |
| `{http.auth.auth_json.error}` | Set only when the check failed for a technical reason, such as the auth service being unreachable. Empty when a user was simply denied. |

That last one is useful for alerting. A denied user and a broken auth service both produce 401, but only the broken service fills in this placeholder and writes an error to the log.

## Example: Cloud Foundry service dashboards

Cloud Foundry exposes `/v3/service_instances/:guid/permissions`, which returns `{"manage": true, "read": true}` for the current browser session. This config puts a dashboard behind it, with read and manage treated separately.

```caddy
dashboard.example.com {
	auth_json {
		endpoint https://api.cf.example.com/v3/service_instances/{http.request.uri.path.1}/permissions
		forward_headers Cookie
		claim can_read   /read
		claim can_manage /manage
	}

	@can_read   expression {vars.can_read} == true
	@can_manage expression {vars.can_manage} == true
	@manage_path path /dashboard/*/manage/*

	route {
		handle @manage_path {
			route {
				reverse_proxy @can_manage dashboard-app:8080
				respond "Read only session." 403
			}
		}
		handle {
			route {
				reverse_proxy @can_read dashboard-app:8080
				respond "Not authorized." 403
			}
		}
	}
}
```

## Things to know

**Wrap `reverse_proxy` and `respond` in a `route` block.** Caddy sorts directives by its own order, and `respond` runs before `reverse_proxy`. Without `route`, a catch all `respond` wins and your proxy never runs, so everyone gets denied. A `route` block keeps the order you wrote.

**Path placeholders start at 0 after the leading slash.** In `/dashboard/si-alpha/overview`, `{http.request.uri.path.0}` is `dashboard` and `{http.request.uri.path.1}` is `si-alpha`.

**A placeholder in `endpoint` fills exactly one path segment.** This is a safety rule, described below. Something like `endpoint http://auth{http.request.uri}` will be refused.

**The auth request has no body.** Only the method, the URL, and the headers you list are sent. If your service needs a form body or a JSON payload, such as an OAuth 2.0 introspection endpoint, this plugin cannot talk to it yet.

**Large whole numbers lose precision.** JSON numbers are decoded as 64 bit floats, so integers above about 9 quadrillion are not exact. If your user IDs are large numbers, have your auth service send them as JSON strings.

**A missing field is left unset, not set to false.** If your service omits `manage`, then `{vars.can_manage}` is empty rather than `false`. This lets you tell "denied" apart from "never mentioned".

## Security notes

**Redirects are not followed.** Auth services often answer "not logged in" with a redirect to a login page, and that page usually returns 200. Following it would let everyone in. The redirect is treated as a denial.

**`forward_headers` is a strict allow list.** Only the fields you name are sent to the auth service. Nothing is forwarded by default.

**A placeholder cannot move the auth request somewhere else.** Placeholder values often come from the request itself, which means a client can influence them. Without a check, a header of `../health?` would turn `/tenants/{tenant}/permissions` into `/health`, which is usually an open endpoint that returns 200, and everyone would be let in. The expanded URL is therefore refused unless it keeps the configured scheme, host, and number of path segments.

**Oversized bodies are refused, not cut short.** A body trimmed at the limit can still be valid JSON while missing the field that would have denied access. Anything over `max_size` fails the check instead.

## Using JSON config

The module ID is `http.authentication.providers.auth_json`.

```json
{
  "handler": "authentication",
  "providers": {
    "auth_json": {
      "endpoint": "http://auth-service:9091/verify",
      "forward_headers": ["Cookie"],
      "claims": { "can_manage": "/manage" },
      "user_id": "/user/id",
      "timeout": "10s",
      "max_size": 1048576
    }
  }
}
```

## Building from source

```bash
git clone https://github.com/faiyaz032/caddy-auth-json
cd caddy-auth-json
go test ./...
xcaddy build --with github.com/faiyaz032/caddy-auth-json=$(pwd)
```

## License

Apache 2.0. See [LICENSE](LICENSE).
