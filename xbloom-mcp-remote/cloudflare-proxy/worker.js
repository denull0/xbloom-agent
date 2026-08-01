// OAuth discovery front for the xbloom-mcp Supabase Edge Function.
//
// Supabase's own project gateway owns every path outside a handful of fixed
// service prefixes (/rest/v1, /auth/v1, /functions/v1, ...). Anything else,
// including /.well-known/* and /authorize at the bare origin, 404s before it
// ever reaches the edge function. OAuth clients (including Claude's MCP
// connector) derive the authorization/token endpoints from the bare origin of
// the server URL, not the deeper /functions/v1/xbloom-mcp path — so discovery
// can never succeed directly against the Supabase URL.
//
// This Worker owns the bare origin instead: it answers the two well-known
// discovery documents itself (self-referential, pointing back at the Worker),
// and transparently proxies every other request through to the real function.

const UPSTREAM = "https://qvuxqpndhyhnykzcvgol.supabase.co/functions/v1/xbloom-mcp";

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

    // Everything else — /authorize, /token, /register, /sse, /message, and the
    // JSON-RPC root — proxies straight through, path and query preserved.
    //
    // Built from scratch rather than `new Request(upstreamUrl, request)`: reusing
    // the incoming Request carries its Host header (this Worker's own hostname)
    // through to the fetch, and Supabase's Cloudflare-fronted edge rejects that
    // as a same-network loop (error 1042). Dropping Host lets fetch() set it
    // correctly for the upstream origin.
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
