# Self-hosting fixes

Two bugs in `xbloom-mcp/index.ts` prevent a self-hosted deployment from working.
Neither is visible to the upstream author: both are masked when the server runs on
the project the code was written against.

## 1. BASE_URL hardcoded to the upstream project

Adding the connector in Claude fails with "Couldn't register with XBloom MCP's
sign-in service."

`const BASE_URL = "https://ramaokxdyszcqpqxmosv.supabase.co/..."` is used to build
the OAuth discovery document, so a self-hosted server advertises the *upstream*
`/authorize`, `/token` and `/register`. The client reads discovery from your server
and then posts its dynamic client registration to someone else's, which fails.

Fix: derive it from `SUPABASE_URL`, injected into every edge function.

Verify: `curl https://<ref>.supabase.co/functions/v1/xbloom-mcp/.well-known/oauth-authorization-server`
should carry your own project ref in every endpoint.

## 2. Session key is not stable across requests

`xbloom_login` returns success; the very next call returns "You need to log in
first", indefinitely.

Edge function logs, three consecutive cycles:

    {"event":"session.store","key":"5b66dc0e","ok":true}
    {"event":"session.lookup","key":"b36419c2","found":false,"hasRow":false}

| cycle | write key (login) | read key (list) |
|-------|-------------------|-----------------|
| 1 | 5b66dc0e | b36419c2 |
| 2 | 680b867c | d46b34a4 |
| 3 | 21dcdd34 | 917f1eab |

The write always lands; the read always looks for a key that was never written.
This rules out a failing write (would log `ok:false`), a rotated service key
(would log `hasRow:true, found:false` plus `session.decrypt_failed`), and an
unauthenticated connection (would log `key:"<empty>"`).

Cause: the server mints a key at `initialize` and returns it in `Mcp-Session-Id`,
expecting the client to echo it back. It does not, so every tool call starts a
fresh cycle with a fresh key. The session storage is correct; the key it is
indexed by does not survive one request.

Fix: mirror the credentials under a fixed key and fall back to it on lookup miss.

### Scope and trade-off

This assumes a single XBloom account per deployment. On a multi-user deployment
the fallback row would be shared and must not be enabled -- if wanted upstream, it
belongs behind an env flag such as `XBLOOM_SINGLE_USER=true`.

It also widens exposure: the function is deployed with `--no-verify-jwt` and its
URL is unauthenticated, so anyone who knows the URL can use a stored session.
Previously they would also have had to guess the session key. The XBloom password
itself is never stored; what is stored is an AES-256-encrypted session token.

## Deployment note

Migrations must be applied **before** the function is deployed. The function writes
`refresh_token` / `expires_at` and needs `encrypted_creds` nullable; against an
older table every session write fails silently.

    supabase db push
    supabase functions deploy xbloom-mcp --no-verify-jwt
