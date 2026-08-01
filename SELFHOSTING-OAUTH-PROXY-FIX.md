# Self-hosted connector fails with "Couldn't register with xBloom's sign-in service"

Even after applying the fixes in `SELFHOSTING-FIXES.md` (BASE_URL derived from
`SUPABASE_URL`, and the `__single_user__` session mirror), adding the connector
in Claude still fails at the very first step, before any XBloom login happens:

> Couldn't register with xBloom's sign-in service. You can try again, or add
> an OAuth Client ID in the connector settings.

## Root cause

Claude's MCP connector derives the OAuth `authorization_endpoint` /
`token_endpoint` / `registration_endpoint` from the **bare origin** of the
server URL you give it, not the full path. For a self-hosted deployment the
server URL is necessarily something like:

```
https://<project-ref>.supabase.co/functions/v1/xbloom-mcp
```

So the client ends up trying:

```
https://<project-ref>.supabase.co/authorize
https://<project-ref>.supabase.co/.well-known/oauth-authorization-server
```

i.e. at the bare project origin, dropping the `/functions/v1/xbloom-mcp`
prefix entirely. This isn't a bug in `xbloom-mcp/index.ts` — the function's
own `.well-known` handlers under `/functions/v1/xbloom-mcp/.well-known/*`
already return the correct, self-referential discovery document (verified
with curl). The problem is that path is never reached.

Every Supabase project sits behind a fixed platform gateway that only routes
a handful of prefixes (`/rest/v1`, `/auth/v1`, `/storage/v1`,
`/functions/v1`, ...). Anything else at the bare origin — including
`/authorize` and `/.well-known/*` — is intercepted by that gateway before it
reaches any deployed function, and returns:

```json
{"error":"requested path is invalid"}
```

Confirmed directly:

```
curl https://<project-ref>.supabase.co/.well-known/oauth-authorization-server
→ 404 {"error":"requested path is invalid"}

curl https://<project-ref>.supabase.co/authorize?...
→ 404 {"error":"requested path is invalid"}   # same error the browser shows
```

This is why the upstream author's single hosted instance was unaffected —
irrelevant to whether it's the author's project or a self-hosted one, this
would break *any* deployment whose MCP endpoint lives under a subpath rather
than at a domain's root. It happened to surface now because self-hosting is
the first time someone stood this up on a fresh project and hit the OAuth
setup flow freshly (an already-authorized upstream connection wouldn't
re-trigger discovery).

**No code change inside the Supabase Edge Function can fix this.** The bare
origin is owned by Supabase's own gateway, not by project code — nothing
deployed under `/functions/v1/...` can ever answer requests at `/authorize`
or `/.well-known/...` at the root.

## Fix: a tiny reverse proxy in front of the Supabase URL

Put a small edge proxy in front (Cloudflare Workers free tier works well)
that:

1. Answers `/.well-known/oauth-authorization-server`,
   `/.well-known/openid-configuration`, and
   `/.well-known/oauth-protected-resource` **itself**, self-referential to
   the proxy's own origin.
2. Transparently forwards everything else (`/authorize`, `/token`,
   `/register`, `/sse`, `/message`, and the JSON-RPC root) through to the
   real Supabase function.

```js
// worker.js
const UPSTREAM = "https://<project-ref>.supabase.co/functions/v1/xbloom-mcp";

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const origin = url.origin;

    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json({
        resource: origin,
        authorization_servers: [origin],
        bearer_methods_supported: ["header"],
      });
    }

    if (
      url.pathname === "/.well-known/oauth-authorization-server" ||
      url.pathname === "/.well-known/openid-configuration"
    ) {
      return json({
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        registration_endpoint: `${origin}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
        code_challenge_methods_supported: ["S256", "plain"],
      });
    }

    // Built from scratch rather than `new Request(upstreamUrl, request)`:
    // reusing the incoming Request carries its Host header (the proxy's own
    // hostname) through to fetch(), and Supabase's Cloudflare-fronted edge
    // rejects that as a same-network loop (Cloudflare error 1042). Dropping
    // Host lets fetch() set it correctly for the upstream origin.
    const upstreamUrl = UPSTREAM + url.pathname + url.search;
    const headers = new Headers(request.headers);
    headers.delete("host");
    const upstreamRequest = new Request(upstreamUrl, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "manual",
    });
    return fetch(upstreamRequest);
  },
};
```

```toml
# wrangler.toml
name = "xbloom-mcp-oauth-proxy"
main = "worker.js"
compatibility_date = "2026-08-01"
```

Deploy with `wrangler deploy` (or `deno run -A npm:wrangler deploy` if you
don't want to install Node — Deno's npm compatibility runs wrangler fine).
Then point the Claude connector at the **Worker's URL**, not the raw
Supabase URL. Leave OAuth Client ID/Secret blank in the connector — dynamic
client registration now works correctly since discovery is self-referential.

### Gotcha hit along the way

The first deploy of the proxy returned Cloudflare error 1042 on any POST
(`/register`, `/token`) while GETs worked fine. Cause: constructing the
proxied request as `new Request(upstreamUrl, request)` carries the original
`Host` header through, and Supabase's own Cloudflare-fronted edge treats a
mismatched Host as a same-network loop and blocks it. Fix: build the request
from scratch, explicitly dropping the `Host` header (see code above) so
`fetch()` sets it correctly for the upstream origin.

## Suggested upstream fix

Given this affects any deployment where the MCP endpoint isn't at a domain
root, it'd be worth either:

- Documenting the proxy requirement directly in `SELFHOSTING-FIXES.md`, or
- Having `xbloom-mcp`'s own handler serve a 401 with a `WWW-Authenticate:
  Bearer resource_metadata="..."` header per RFC 9728 on unauthenticated
  requests, in case that lets compliant clients skip bare-origin guessing
  entirely (untested — the proxy above is the confirmed-working fix).
