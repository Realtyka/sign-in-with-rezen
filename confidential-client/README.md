# Login with reZEN

This is the server-side (`confidential-client`) sample. If your app has no backend
that can hold a secret, use the `public-client` project instead (see the root
README).

A minimal, runnable example of "Login with reZEN" — the OAuth 2.1 authorization code
flow with PKCE and OpenID Connect identity. Sign in, and the sample verifies your
identity and calls one Real API on your behalf.

Flow, in one line: authorize (PKCE) → sign in and consent → code exchange → verify
identity → call an API.

## Prerequisites

Ask your Real contact to register a client for you, with the redirect URI
`http://[::1]:4500/callback` and the scopes you need. Loopback redirect URIs like this
one are for development registrations only.

Full integration details — registration, scopes, token rules, errors, and the security
checklist — are in the vendor integration guide at
[`https://keymaker-oauth.therealbrokerage.com/docs`](https://keymaker-oauth.therealbrokerage.com/docs).
If your contact gives you a different issuer for development, the same guide is served at
`<issuer>/docs` there.

## Run

```sh
cp .env.example .env
# fill in ISSUER, CLIENT_ID, CLIENT_SECRET (leave blank for a public client), and SCOPES
npm start
```

Open `http://[::1]:4500`. Use `[::1]`, not `localhost` or `127.0.0.1` — that's what
your redirect URI is registered as (see the guide's errors section).

## What happens

1. You click **Login with reZEN**; the sample generates PKCE and sends you to `/authorize`.
2. You sign in and approve the consent screen (once — later sign-ins skip it).
3. reZEN redirects back with a one-time authorization code.
4. The sample exchanges the code for tokens (with your client secret if you have one,
   PKCE alone if not).
5. It verifies the returned identity token, then fetches your identity from `/userinfo`.
6. It calls `/me` — your own profile — using the access token as an API key.

## What the page shows

Your verified identity (`sub`, `name`, `email`, `yentaId`), the scope you actually
granted, your profile from `/me` (`displayName`, `type`), and the steps above as
they happened.

## Test

```sh
npm test
```

Runs entirely offline against a stub issuer and a stub API — no network access, no
real credentials.

## Notes

- The authorization code is single-use and expires in 60 seconds.
- The access token is an opaque API key — sent as `x-api-key` to Real APIs, never as
  `Authorization: Bearer` (that header is used only for `/userinfo`).
- The identity token is verified once, on receipt, and then discarded — it's identity
  evidence, not a credential.
- Refresh and revoke aren't implemented here — see the guide's refresh and security
  sections.
- `/login` and `/logout` are plain GETs with no CSRF token, and the session cookie has
  no `Secure` flag — both fine for this loopback sample; add CSRF protection and
  `Secure` before running this on a real host.
