# Sign in with reZEN — public client

A minimal, runnable example of "Sign in with reZEN" that runs entirely in the browser: a
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

**Cross-origin requests.** This app calls the issuer's token, JWKS, userinfo, revocation,
and discovery endpoints directly from the browser, from your app's own origin. If the
issuer does not allow cross-origin requests from that origin, the code exchange fails
with a CORS error in the browser console rather than an error from reZEN itself. If you
see that, ask your Real contact to confirm your origin is allowed. The browser also
calls the Real API directly, sending the access token as a custom `x-api-key` header —
the API host must allow that header for your origin too, or the preflight fails the
same way.

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
2. You click **Sign in with reZEN**; a popup opens `/authorize` with a fresh PKCE
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
7. **Disconnect** calls the issuer's `/revoke` — with the refresh token if this tab still
   holds one, and with the access token if it doesn't (after a reload it never does) —
   and then clears the tab's session. **Sign out** clears the tab's session and nothing
   else.

## What the page shows

Your verified identity (`sub`, `name`, `email`, `yentaId`), the scope you actually
granted, your profile (`displayName`, `type`), and the steps above as they happened —
and, at the bottom, the two ways out: **Sign out** and **Disconnect**. After a
disconnect the landing says which token was revoked, or that the revoke did not succeed.

The button follows the reZEN sign-in button specification — filled and outline
variants, three fill styles (navy, reZEN, neutral), four sizes, a wordmark layout and a
mark-and-text layout, and the hover, pressed, loading and disabled states; the landing
shows the filled and outline pairing on a light and a dark background, with the other
styles beneath each.

## Test

```sh
npm test
```

Runs entirely offline against a stub issuer and a stub API — no network access, no
real credentials, no browser. It drives the protocol module (PKCE, the authorize
request, the code exchange, id_token verification, `/userinfo`, the API call, and
`/revoke`) and boots the static file server. Run it from a full checkout of this
repository: part of the suite is a shared id_token test vector at
`../test-vectors/id-token.json`, which the server-side sample's suite runs through its
own verifier too, so the two verifiers cannot drift. The popup UI itself — the click, the popup window, the
`BroadcastChannel` handoff — is verified by hand in a real browser against the same
kind of stub.

## Notes

- Where tokens live: the access token is held in memory with a per-tab `sessionStorage`
  mirror, so a reload of this tab stays signed in and closing the tab signs you out; it
  is never written to `localStorage` or a cookie. The refresh token is held in memory
  only and is never persisted anywhere — it is the long-lived credential, and a browser
  has no safe place to keep it between page loads. Any script running on this app's
  origin can read `sessionStorage`, so keep the origin free of untrusted code. If your
  app has a backend, prefer the confidential client, which keeps every token
  server-side.
- The popup hands its result to the main page over a `BroadcastChannel` (and
  `window.opener.postMessage` too, when an opener is still present, belt and braces) —
  the issuer's pages may set a `Cross-Origin-Opener-Policy` header that detaches
  `window.opener` from the page that opened it, so the result travels the channel
  either way. The popup closes itself once the main page acknowledges the result over
  that same channel.
- The authorization code is single-use and expires in 60 seconds.
- The access token is an opaque API key — sent as `x-api-key` to Real APIs, never as
  `Authorization: Bearer` (that header is used only for `/userinfo`).
- The identity token is verified once, in the browser, on receipt, and then discarded —
  it's identity evidence, not a credential.
- **Sign out and Disconnect are different actions, and only one of them talks to reZEN.**
  Sign out forgets the tokens in this tab and leaves your tokens at reZEN alone until
  they expire. Disconnect is the guide's §8 action — it calls `/revoke` first, then
  forgets them. The tradeoff: sign out could revoke the access token too (that would kill
  exactly that one key), and leaving it live for the rest of its 12 hours is a real, if
  small, cost. This sample doesn't, for two reasons — a user who clicks "sign out"
  expects a local, reversible act, and collapsing the two buttons into one would hide the
  distinction the guide draws and vendors have to implement. If your product wants sign
  out to revoke, the change is one call in `signOut()`; say so in your UI.
- **Disconnect revokes whichever token this tab still has.** With a refresh token in
  hand it sends that, which revokes the whole family and the API keys minted under it.
  After a reload the refresh token is gone — it is deliberately never persisted — so it
  sends the access token instead, which revokes that one key. That is the honest limit of
  a browser-only client, and the landing says which of the two happened. A confidential
  client keeps the refresh token server-side and never has the weaker case.
- Your stored consent survives a disconnect. Signing in again is a redirect round-trip,
  not a second consent screen — that is by design, and worth saying in your own UI so
  "disconnect" doesn't read as "delete everything".
- Refresh isn't implemented here — a public client has nowhere safe to keep a refresh
  token between page loads; see the guide's refresh section.
