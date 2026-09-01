---
name: build-integration
description: This skill should be used when the user asks to "build a Sign in with reZEN integration", "add reZEN login to my project", "port the reZEN samples to my stack", "implement OAuth sign-in with reZEN here", or otherwise wants a new "Sign in with reZEN" integration built in another project, using this repository's samples as the template but written in that project's own language, framework, and conventions.
argument-hint: "<path-to-target-project> [--type confidential|public]"
---

# Build an Integration From the Samples

Given the path to a target project, build a "Sign in with reZEN" integration in that project's own
stack, using the exchanges this repository's samples perform as the template — not a port of the
samples' code, a re-implementation of the same protocol steps in idioms the target project already
uses. That freedom is about implementation — language, framework, code shape — not about the
sign-in button's appearance: Step 6 covers the button, and there the template is not a suggestion.

## Step 1: Read the reference

Read the root `README.md`, both sample `README.md` files, both `oidc.js` files
(`confidential-client/src/oidc.js`, `public-client/public/oidc.js`), and
`test-vectors/id-token.json`. These define the exchange list and the reference behaviour for each
exchange — see the numbered list in this repository's `review-integration` skill, which this
skill's checklist mirrors at the end.

## Step 2: Pick the client type

Same rule as the samples: where will the target project's code that talks to the issuer actually
run? A server the integrator controls, holding a secret that never reaches the browser →
confidential. A browser, native app, desktop app, or CLI → public. Use `--type` if passed;
otherwise ask, or infer it from what the target project already is (a backend service vs. a
frontend app vs. a CLI tool) and state the inference before proceeding.

## Step 3: Discover the target's stack

Read the target project's manifest/lockfile and existing code to learn, rather than assume:
- **HTTP client** — the target's existing way of making outbound requests (its own `fetch` wrapper,
  a library already in the manifest, the language's stdlib).
- **Session or state store** — for a confidential (server-side) client: how the target already
  manages server-side session state, if it has one, and what conventions it follows (cookie name,
  store backend, expiry handling).
- **Crypto / JWT library** — is there already a mature, maintained OIDC or JWT library in the
  target's ecosystem? Note candidates and their JWKS-verification support.
- **Config loading** — how the target already reads environment-specific configuration, so the new
  integration's config fits the existing pattern rather than introducing a second one.
- **Test runner** — what the target already uses to run tests, so the new test fits in without a
  new dependency purely for this integration.

## Step 4: Plan the exchange list in the target's idioms

Plan the same exchanges the samples perform, each in the target stack's idioms rather than
transliterated from JavaScript:

1. Discovery (`<issuer>/.well-known/openid-configuration`, verify the returned `issuer`)
2. PKCE (S256 verifier/challenge, generated per attempt)
3. Authorize request (`response_type=code`, `client_id`, `redirect_uri`, `scope`, fresh `state`,
   fresh `nonce`, PKCE challenge)
4. Callback handling with `state` checked before anything else in the response is trusted
5. Token exchange with client authentication by type (Basic + RFC 6749 §2.3.1 form-encoding for
   confidential; `client_id` in the body for public)
6. `id_token` verification (RS256 only, `iss`, `aud`/`azp`, `exp`/`iat` with clock-skew leeway,
   `nonce`)
7. `/userinfo` (the only exchange using `Authorization: Bearer`)
8. API calls with the access token as an API key header (`x-api-key`)
9. Revocation / disconnect (RFC 7009 — token in the body, any response status accepted)
10. Sign-out (local only, no call to the issuer)
11. Token storage appropriate to the client type (server-side only for confidential; in-memory
    access token + `sessionStorage` mirror and in-memory-only refresh token for public — never a
    refresh token in `localStorage` or a cookie)
12. Redirect URI handling (exact match; origin-checked cross-window messaging for a public client
    that uses a popup)
13. Error handling (map the issuer's OAuth/OIDC error codes to something actionable)

Refresh is intentionally out of scope here, same as in the samples — point the target project at
the vendor guide's refresh section if it needs one; do not invent a refresh implementation neither
sample has a reference behaviour for.

## Step 5: Choose the id_token verifier

Prefer the target stack's own established OIDC or JWT library for signature and JWKS verification
when a mature one already exists in that ecosystem — don't hand-roll cryptography where the stack
has a trusted answer. When no such library exists (or the target's constraints rule it out), port
the sample's `verifyIdToken()` logic: RS256-only, JWKS lookup by `kid`, then `iss`/`aud`/`azp`/
`exp`/`iat`/`nonce` checks in that order, matching the two samples' shared behaviour.

Either way, **run `test-vectors/id-token.json` through the result as a test.** The vector contains:
- `jwks` — one RSA public key, and `params` — the `issuer`, `clientId`, and `nonce` the vector's
  tokens were signed for.
- `valid` — one well-formed RS256 `id_token` signed by the published key, plus the exact `claims`
  object verification should return for it.
- `invalid` — ten tokens, each breaking exactly one check, with an `expect` string naming what
  the rejection reason should contain: a token signed by a key not in the JWKS (wrong signature),
  an HS256 token (wrong algorithm), a `kid` naming a key absent from the JWKS, a mismatched `iss`,
  an `aud` that excludes the client, a multi-value `aud` with no `azp` naming the client, an `azp`
  naming a different client, an expired token, an `iat` in the future, and a mismatched `nonce`.

The test must assert: verifying `valid.idToken` against `jwks`/`params` succeeds and returns
exactly `valid.claims`; verifying each `invalid[].idToken` against the same `jwks`/`params` fails,
with a rejection reason containing that case's `expect` string. Both samples' own test suites
(`confidential-client/test/smoke.mjs`, `public-client/test/smoke.mjs`) run this same vector through
their own verifiers this same way — use them as a model for the assertions if the target's test
runner needs an example.

## Step 6: Port the sign-in button

The sign-in affordance MUST use the `.rezen-btn` template, ported faithfully into the target's
idiom — colors, metrics, radius, and states carried over verbatim. Tailwind, CSS-in-JS, or plain
CSS are all fine; a different implementation technique is not license to redesign the button.
Reference `public-client/public/style.css` (~L207–373: two variants — filled, outline — three fill
styles — navy, rezen, neutral — four sizes, and the hover/pressed/loading/disabled states) and
`confidential-client/src/server.js`'s `loginButton()` (~L709) and `specimen()` (~L722).

- **Label and wordmark.** The label is "Sign in with" followed by the wordmark as an IMAGE, never
  recolored text: the white asset on the filled variant, the black asset on the outline variant
  (`rezen-logo-white.svg` / `rezen-logo-black.svg`). Copy both SVGs into the target repo.
- **Variant and fill are a stated decision**, not a default left implicit: filled on a light
  ground, outline on a dark one; fill style `navy` by default, `rezen` (blue) where the host's own
  primary call-to-action is already reZEN blue. Say which was chosen and why.
- **Loading state.** Wire it even though the samples don't all model it: `confidential-client`'s
  `loginButton()` renders a plain anchor because that page carries no script by design (its CSP
  allows none), so its `is-loading`/disabled CSS sits unused there — but `public-client`'s
  `app.js` (`setLoading()`) does wire it, and is the model to port. On click, add `is-loading` and
  `aria-busy="true"` to the button before navigating away; return the button to rest on the
  error-return path, the same way `setLoading(undefined)` runs in a `finally` once the flow ends
  by anything other than a fresh page navigation.
- **Popup is public-client-only.** A confidential integration's exchange runs server-side behind a
  secret, so it keeps `loginButton()`'s plain-anchor full-page redirect — never a popup.

## Step 7: Deliver

- **Config template** mirroring the sample `.env.example` files' keys: `ISSUER`, `CLIENT_ID`,
  `CLIENT_SECRET` (confidential only, blank means public), `REDIRECT_URI`, `SCOPES`, `API_BASE` —
  in whatever config format the target project already uses.
- **The flow itself**, implemented per Step 4's list in the target's idioms.
- **The sign-in button**, per Step 6: the ported `.rezen-btn` template, the wordmark SVG assets
  copied in, and the loading state wired.
- **A smoke test** that includes, at minimum, the `id_token` vector test from Step 5, run offline
  with no network access and no real credentials — the same shape as the samples' own
  `npm test`.
- **A README section** for the target project that links to the vendor integration guide at
  `<issuer>/docs` for registration, scopes, token rules, errors, and the security checklist,
  rather than restating any of it.

## Step 8: Closing checklist

End with a checklist that mirrors the `review-integration` skill's exchange list, one line per
exchange, so a later review of this integration and this build agree on what "done" covers:

- [ ] Discovery reads every endpoint from `<issuer>/.well-known/openid-configuration`; no
      hardcoded endpoint URL
- [ ] PKCE (S256) generated fresh per attempt
- [ ] Authorize request sends `response_type=code`, fresh `state`, fresh `nonce`, PKCE challenge
- [ ] Callback checks `state` before trusting anything else in the response
- [ ] Token exchange authenticates by client type (Basic + form-encoding, or `client_id` in body)
- [ ] `id_token` verified: RS256 only, `iss`, `aud`/`azp`, `exp`/`iat`, `nonce`
- [ ] `id_token` verification tested against `test-vectors/id-token.json` (valid + all invalid cases)
- [ ] `/userinfo` is the only place `Authorization: Bearer` is used
- [ ] API calls send the access token as `x-api-key`, not Bearer
- [ ] Revocation sends the token in the POST body and treats the response as idempotent, not an oracle
- [ ] Sign-out is local only; no call to the issuer
- [ ] Token storage matches the client type (server-side only, or in-memory + non-persisted refresh)
- [ ] Redirect URI matched exactly; cross-window messages origin-checked (public client)
- [ ] Issuer error codes mapped to actionable messages
- [ ] Config template mirrors the sample `.env.example` keys
- [ ] README links the vendor guide instead of restating it
- [ ] Sign-in button ports the `.rezen-btn` template verbatim (colors, metrics, radius, states) —
      not a redesign in the target's own visual language
- [ ] Label is "Sign in with" + the wordmark image (white on filled, black on outline); the SVG
      assets are copied into the target repo, never recolored as text
- [ ] Variant/fill is a stated decision (filled/outline by ground, navy default vs. `rezen`)
- [ ] Loading state (`is-loading` + `aria-busy`) is set on click and cleared on the error-return
      path
- [ ] Popup is used only in a public client; a confidential client keeps the plain-anchor
      full-page redirect
