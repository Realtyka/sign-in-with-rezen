---
name: review-integration
description: This skill should be used when the user asks to "review an integration", "review my client's Sign in with reZEN implementation", "check my OAuth client against the reference samples", "compare my code to the reZEN samples", or otherwise wants an outside client implementation of "Sign in with reZEN" checked against the reference behaviour in this repository's `confidential-client/` and `public-client/` samples.
argument-hint: "<path-to-client-code> [--type confidential|public]"
---

# Review an Integration Against the Samples

Given the path to another codebase's "Sign in with reZEN" client, compare what it does against
this repository's reference samples and produce a divergence table an engineer can act on
directly. This skill can be run by a reviewer at the issuer's own organisation, checking a
partner's integration, or by the integrating developer, checking their own work before it ships —
the steps and the output are the same either way.

## Step 1: Classify the client type

Before anything else, decide which sample the client under review should be compared against. The
rule is the one this repository's own README uses: **client type follows from where the code
runs, not from how much the integrator trusts the app.**

- Code that runs on a server the integrator controls, which can hold a secret and never sends it
  to the browser → compare against `confidential-client/`.
- Code that runs in the user's browser, a native app, a desktop app, or a CLI — anywhere a user
  could extract an embedded secret — → compare against `public-client/`.

If `--type` was passed, use it, but verify it against the evidence (a client secret configured
anywhere reachable from the browser means the classification is wrong regardless of the flag —
report that as a finding in its own right, HIGH, before doing anything else). If no `--type` was
passed, determine it from the client's own code: is there a `client_secret`-shaped config value
that never leaves server-side code? Is the code that talks to the issuer bundled for the browser,
or does it ship in a mobile/CLI binary? State the classification and the evidence for it at the
top of the report — everything below depends on it.

## Step 2: Read the reference

Read both sample `README.md` files, the root `README.md`, and both samples' `oidc.js` files
(`confidential-client/src/oidc.js`, `public-client/public/oidc.js`) to refresh the exact reference
behaviour before comparing. `test-vectors/id-token.json` is the shared id_token vector both
samples' verifiers run through their own copy — it doubles as a ready-made set of valid/invalid
tokens to probe the client under review with, if it exposes a way to do that offline.

## Step 3: Locate each exchange in the client under review

Search the client's code for each exchange below. An exchange the client doesn't implement at all
is itself a finding (severity depends on whether the sample it's being compared against implements
it — see the note on refresh). The last item is not an exchange — the sign-in button — but it is
reviewed the same way, against the same reference, and the `build-integration` skill's closing
checklist mirrors this list including it.

### The exchange list

1. **Discovery** — does the client fetch `<issuer>/.well-known/openid-configuration` and derive
   every other endpoint from it, or does it hardcode an endpoint URL anywhere? Reference:
   `discover()` in either sample's `oidc.js` — identical in both, and checks the returned
   `issuer` matches the one requested (OIDC Discovery 4.3).
2. **PKCE** — is a `code_verifier`/`code_challenge` pair generated per attempt, with
   `code_challenge_method=S256`? Reference: `pkce()` in either sample's `oidc.js`.
3. **Authorize request** — does it send `response_type=code`, `client_id`, `redirect_uri`,
   `scope`, a freshly generated `state`, a freshly generated `nonce`, and the PKCE challenge?
   Reference: `authorizeUrl()` in either sample's `oidc.js`.
4. **Callback and state check** — is `state` checked against what was sent, before anything else
   in the response (including an `error` parameter) is trusted? Reference:
   `public-client/public/callback.js` checks `state` first for exactly this reason — a crafted
   `?error=...` callback URL must not be able to show a tab an error page for a flow it never
   started. The confidential sample's equivalent is its `/callback` route in
   `confidential-client/src/server.js`.
5. **Token exchange and client authentication** — confidential clients authenticate with HTTP
   Basic, both `client_id` and `client_secret` form-encoded per RFC 6749 §2.3.1 before the `:`
   join and base64 (reference: `formEncode()` and `exchangeCode()` in
   `confidential-client/src/oidc.js`); public clients send `client_id` in the body and never a
   secret or an `Authorization` header (reference: `exchangeCode()` in
   `public-client/public/oidc.js`).
6. **`id_token` verification** — signature (RS256 only — the header's `alg` is never trusted to
   choose the algorithm), `iss`, `aud` (with the `azp` rule when `aud` has more than one value),
   `exp`/`iat` with a small clock-skew leeway, and `nonce`. Reference: `verifyIdToken()` — written
   twice in this repository, once against Node's `crypto` (`confidential-client/src/oidc.js`) and
   once against the Web Crypto API (`public-client/public/oidc.js`), deliberately identical in
   what each accepts, rejects, and says when it rejects.
7. **`/userinfo`** — the only exchange that uses `Authorization: Bearer`. Reference: `userinfo()`
   in either sample's `oidc.js`.
8. **API call header** — does a resource API call send the access token as an API key header
   (`x-api-key`), not `Authorization: Bearer`? Reference: `apiCall()` in either sample's `oidc.js`.
9. **Refresh** — neither sample implements token refresh (see each README's "Refresh isn't
   implemented here" note, which points at the vendor guide's refresh section). Its absence in the
   client under review is not itself a finding; if the client does implement refresh, review it
   against the vendor guide directly, since neither sample is a reference for it.
10. **Revocation / disconnect** — does "disconnect" call the issuer's revocation endpoint (RFC
    7009) with the token in the POST body (never a URL, never a log line) before dropping local
    state, and does it treat any response status as acceptable rather than using it as an oracle
    for whether the token existed (RFC 7009 §2.2)? Reference: `revoke()` in either sample's
    `oidc.js`, called from `/disconnect` in `confidential-client/src/server.js` and from
    `disconnect()` in `public-client/public/app.js`.
11. **Sign-out** — does "sign out" stay purely local (clear the client's own session/tokens) and
    make no call to the issuer? Both samples draw this distinction deliberately — conflating
    sign-out with disconnect is a design regression worth flagging even though nothing is
    insecure about it.
12. **Token storage, by client type** — confidential clients must keep every token server-side,
    never sending one to the browser (reference: the session store in
    `confidential-client/src/server.js`). Public clients keep the access token in memory with a
    per-tab `sessionStorage` mirror and the refresh token in memory only, never persisted
    (reference: the module-level variables in `public-client/public/app.js` and the "Where tokens
    live" note in `public-client/README.md`). A refresh token in `localStorage`, a cookie, or
    anywhere else persistent in a public client is a HIGH finding on its own.
13. **Redirect URI handling** — is the redirect URI registered exactly (no wildcard or substring
    matching), and — for a public client whose flow can run in a popup or an iframe-adjacent
    context — is the origin of any cross-window message checked before it's trusted? Reference:
    the `event.origin !== location.origin` check in `public-client/public/app.js`.
14. **Error handling** — are the issuer's OAuth/OIDC error codes (`access_denied`,
    `invalid_scope`, `unauthorized_client`, `invalid_grant`, etc.) mapped to something a user can
    act on, rather than surfaced raw or swallowed silently? Reference: `mapAuthorizeError()` and
    `mapTokenError()` in `confidential-client/src/server.js` and
    `public-client/public/callback.js`.
15. **Sign-in button** — is the sign-in affordance the `.rezen-btn` template ported faithfully
    (colors, metrics, radius, and the hover/pressed/loading/disabled states carried over — the
    implementation technique may differ, the design may not), or a redesign in the host's own
    visual language? Check the same five points the `build-integration` skill's Step 6 requires:
    the label is "Sign in with" followed by the wordmark as an image (white asset on the filled
    variant, black on outline — never recolored text); the variant/fill choice is stated (filled on
    a light ground, outline on a dark one; `navy` by default, `rezen` where the host's own primary
    call-to-action is already reZEN blue); the loading state (`is-loading` + `aria-busy`) is set on
    click and cleared on the error-return path; and a popup appears only in a public client — a
    confidential client keeps the plain-anchor full-page redirect. Reference: `.rezen-btn` in
    `public-client/public/style.css`, `loginButton()` and `specimen()` in
    `confidential-client/src/server.js`, and `setLoading()` in `public-client/public/app.js` for
    the loading state.

## Step 4: Produce the divergence table

For every exchange where the client under review differs from the matching sample's reference
behaviour — including an exchange it omits entirely, where the sample implements it — add a row:

| Exchange | Reference behaviour | Client behaviour | Severity | Fix |
| --- | --- | --- | --- | --- |
| `<name from the list above>` | `<what the matching sample does, cited by file:function>` | `<what the client under review does, cited by file:line if available>` | HIGH \| MEDIUM \| LOW | `<the concrete change>` |

Severity guide:
- **HIGH** — a protocol weakening that an attacker could exploit (missing/weak PKCE, missing
  `state`/`nonce` check, `alg` not pinned to RS256, missing `iss`/`aud`/`exp` check, a secret or
  refresh token persisted somewhere a public client shouldn't keep it, revocation skipped on
  disconnect).
- **MEDIUM** — a correctness or robustness gap that isn't directly exploitable but should be
  fixed (Bearer used somewhere other than `/userinfo`, an API key sent as Bearer instead of
  `x-api-key`, error codes not mapped, redirect URI matching that isn't exact).
- **LOW** — a divergence in shape or polish that doesn't affect security or correctness (sign-out
  and disconnect conflated without a security consequence, a config key named differently, a
  missing `.env.example`-style template, a sign-in button that departs from the `.rezen-btn`
  template — bare text anchor, recolored wordmark, missing loading state, popup in a confidential
  client).

Rows with no divergence are not listed — the table is a punch list, not a full trace.

## Step 5: Verdict

Close with one line: `Verdict: <PASS | PASS WITH FINDINGS | FAIL>` followed by the HIGH/MEDIUM/LOW
counts and a one-sentence rationale — `FAIL` when any HIGH finding remains, `PASS WITH FINDINGS`
when only MEDIUM/LOW remain, `PASS` when the table is empty.
