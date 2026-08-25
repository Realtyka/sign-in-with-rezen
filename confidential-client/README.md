# Sign in with reZEN

This is the server-side (`confidential-client`) sample. If your app has no backend
that can hold a secret, use the `public-client` project instead (see the root
README).

A minimal, runnable example of "Sign in with reZEN" — the OAuth 2.1 authorization code
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

1. You click **Sign in with reZEN**; the sample generates PKCE and sends you to `/authorize`.
2. You sign in and approve the consent screen (once — later sign-ins skip it).
3. reZEN redirects back with a one-time authorization code.
4. The sample exchanges the code for tokens (with your client secret if you have one,
   PKCE alone if not).
5. It verifies the returned identity token, then fetches your identity from `/userinfo`.
6. It calls `/me` — your own profile — using the access token as an API key.
7. **Disconnect** posts to `/disconnect`, which calls the issuer's `/revoke` with your
   refresh token before dropping the session. **Sign out** posts to `/sign-out`, which
   drops the session and nothing else.

## What the page shows

Your verified identity (`sub`, `name`, `email`, `yentaId`), the scope you actually
granted, your profile from `/me` (`displayName`, `type`), and the steps above as
they happened — and, at the bottom, the two ways out: **Sign out** and **Disconnect**.

The button follows the reZEN sign-in button specification — filled and outline
variants, three fill styles (navy, reZEN, neutral), four sizes, a wordmark layout and a
mark-and-text layout, and the hover, pressed, loading and disabled states; the landing
shows the filled and outline pairing on a light and a dark background, with the other
styles beneath each. This page carries no
script, so the link stays static; the loading and disabled state classes are in the
stylesheet for an app that has somewhere to set them.

## Test

```sh
npm test
```

Runs entirely offline against a stub issuer and a stub API — no network access, no
real credentials. Run it from a full checkout of this repository: part of the suite is
a shared id_token test vector at `../test-vectors/id-token.json`, which the browser
sample's suite runs through its own verifier too, so the two verifiers cannot drift.

## Notes

- The authorization code is single-use and expires in 60 seconds.
- The access token is an opaque API key — sent as `x-api-key` to Real APIs, never as
  `Authorization: Bearer` (that header is used only for `/userinfo`).
- The identity token is verified once, on receipt, and then discarded — it's identity
  evidence, not a credential.
- **Sign out and Disconnect are different actions, and only one of them talks to reZEN.**
  Sign out ends this app's session: the server-side session and both tokens in it are
  dropped, and your tokens at reZEN are left alone until they expire. Disconnect is the
  guide's §8 action — it calls `/revoke` with the refresh token first, which revokes the
  whole token family and the API keys minted under it, and then ends the session. The
  tradeoff: sign out could revoke the access token too (that would kill exactly that one
  key), and leaving it live for the rest of its 12 hours is a real, if small, cost. This
  sample doesn't, for two reasons — a user who clicks "sign out" expects a local,
  reversible act, and collapsing the two buttons into one would hide the distinction the
  guide draws and vendors have to implement. If your product wants sign out to revoke,
  the change is one call in `/sign-out`; say so in your UI.
- Your stored consent survives a disconnect. Signing in again is a redirect round-trip,
  not a second consent screen — that is by design, and worth saying in your own UI so
  "disconnect" doesn't read as "delete everything".
- Refresh isn't implemented here — see the guide's refresh section.
- `/sign-out` and `/disconnect` change state, so they are POSTs from a real form, and the
  server serves them only when the request came from this origin (`Sec-Fetch-Site`, or
  `Origin` for anything that doesn't send it); a GET gets a 405 and a cross-site POST a
  403. There is no CSRF token: that check, plus the `SameSite=Lax` session cookie, is the
  whole defence. Add a per-session token if you must support browsers that send neither
  `Sec-Fetch-Site` nor `SameSite`. The session cookie also has no `Secure` flag, which is
  fine for this loopback sample — add it before running this on a real host.
