# Login with reZEN — public client

A minimal, runnable example of "Login with reZEN" that runs entirely in the browser: a
**public client** — no client secret, ever — using PKCE alone to secure the code
exchange. Click the button, a popup completes the sign-in (falling back to a full-page
redirect if the popup is blocked), and the page verifies your identity and calls one
Real API on your behalf.

If your app runs on a server you control — a backend that can hold a secret — use
`confidential-client/` instead: it authenticates the code exchange with the secret
rather than PKCE alone, and it keeps every token server-side. Use `public-client/` when
your app has no backend, or when the code that talks to reZEN runs where a user could
extract a secret from it (a browser tab, a native app, a CLI).

Flow, in one line: click → popup opens `/authorize` (PKCE) → sign in and consent → the
popup exchanges the code and verifies your identity → the result is handed back to the
main page → it calls an API.

## Prerequisites

Ask your Real contact to register a **public** client for you, with the redirect URI
`http://[::1]:4501/callback` and the scopes you need. Loopback redirect URIs like this
one are for development registrations only.

Full integration details — registration, scopes, token rules, errors, and the security
checklist — are in the vendor integration guide at
[`https://keymaker-oauth.therealbrokerage.com/docs`](https://keymaker-oauth.therealbrokerage.com/docs).
If your contact gives you a different issuer for development, the same guide is served at
`<issuer>/docs` there.

**Cross-origin requests.** This app calls the issuer's token, JWKS, userinfo, and
discovery endpoints directly from the browser, from your app's own origin. If the
issuer does not allow cross-origin requests from that origin, the code exchange fails
with a CORS error in the browser console rather than an error from reZEN itself. If you
see that, ask your Real contact to confirm your origin is allowed.

## Run

```sh
cp .env.example .env
# fill in ISSUER, CLIENT_ID, and SCOPES
npm start
```

Open `http://[::1]:4501`. Use `[::1]`, not `localhost` or `127.0.0.1` — that's what
your redirect URI is registered as (see the guide's errors section).

## What happens

1. The page loads discovery and precomputes a PKCE pair.
2. You click **Login with reZEN**; a popup opens `/authorize` with a fresh PKCE
   challenge, state, and nonce. If the browser blocks the popup, the page falls back to
   a full-page redirect through the same URL instead.
3. You sign in and approve the consent screen (once — later sign-ins skip it).
4. reZEN redirects the popup (or the page) back with a one-time authorization code.
5. The callback page checks `state` and `iss`, then exchanges the code for tokens —
   PKCE alone, no secret, `client_id` in the body — and verifies the returned identity
   token in the browser.
6. The result is handed to the main page over a `BroadcastChannel` (and `postMessage`
   when the popup still has an opener); the main page fetches `/userinfo`, then calls
   one Real API — your own profile — using the access token as an API key.

## What the page shows

Your verified identity (`sub`, `name`, `email`, `yentaId`), the scope you actually
granted, your profile (`displayName`, `type`), and the steps above as they happened.

## Test

```sh
npm test
```

Runs entirely offline against a stub issuer and a stub API — no network access, no
real credentials, no browser. It drives the protocol module (PKCE, the authorize
request, the code exchange, id_token verification, `/userinfo`, the API call) and boots
the static file server. The popup UI itself — the click, the popup window, the
`BroadcastChannel` handoff — is verified by hand in a real browser against the same
kind of stub.

## Notes

- The access token is held in memory and mirrored (with its expiry, granted scope, and
  identity claims) into `sessionStorage`, so a reload of this tab stays signed in. The
  refresh token is held in memory only and is never written to `sessionStorage` or
  anywhere else — it is gone after a reload; the access token survives until it expires.
- The popup hands its result to the main page over a `BroadcastChannel`, not only
  `window.opener.postMessage` — some issuer pages set a
  `Cross-Origin-Opener-Policy` header that detaches `window.opener`, and the channel
  works either way.
- The authorization code is single-use and expires in 60 seconds.
- The access token is an opaque API key — sent as `x-api-key` to Real APIs, never as
  `Authorization: Bearer` (that header is used only for `/userinfo`).
- The identity token is verified once, in the browser, on receipt, and then discarded —
  it's identity evidence, not a credential.
- Refresh and revoke aren't implemented here — a public client has nowhere safe to keep
  a refresh token between page loads; see the guide's refresh and security sections.
