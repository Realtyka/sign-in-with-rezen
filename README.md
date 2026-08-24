# Sign in with reZEN

Two runnable samples of "Sign in with reZEN" — the OAuth 2.1 authorization code flow
with PKCE and OpenID Connect identity. Each one signs a Real agent in, verifies
their identity, and calls one Real API on their behalf. Full integration details —
registration, scopes, token rules, errors, and the security checklist — are in the
vendor integration guide at
[`https://keymaker-oauth.therealbrokerage.com/docs`](https://keymaker-oauth.therealbrokerage.com/docs).

## Which one?

**Client type follows from where the code runs, not from how much you trust the app.**

|                                  | `confidential-client/`                          | `public-client/`                                                                             |
| -------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| Where the code runs               | A server you control                              | The user's browser, native, desktop, or CLI                                                     |
| Client secret                     | Yes — held server-side, never sent to the browser | None                                                                                             |
| How the code exchange authenticates | Client secret + PKCE                            | PKCE alone                                                                                      |
| Flow shape                        | Full-page redirect; the server handles the callback | Popup with a full-page redirect fallback; the browser handles the callback                     |
| Where tokens live                 | Server-side session                               | Access token in memory with a per-tab `sessionStorage` mirror; refresh token in memory only, never persisted |
| Environment prerequisite          | None beyond registration                          | The issuer must allow cross-origin requests from the app's origin to its token, JWKS, userinfo, and discovery endpoints; the API host must allow the `x-api-key` header for that origin too |
| Pick it when                      | You have a backend — the recommended choice whenever one exists | You have no backend that can hold a secret                                                      |

If you have a backend, use the confidential client. A secret in a browser bundle or
a native binary is not a secret.

Both samples request the same scopes and call the same API; the difference is only
who holds the credential and how the callback is handled.

## Run

Pick a project, `cd` into it, and follow its README — `cp .env.example .env`, fill
in your registered client's values, `npm start`, `npm test`. Node ≥ 18, no
dependencies.

## Layout

- `confidential-client/` — server-side sample (port 4500)
- `public-client/` — browser sample (port 4501)
- `CLAUDE.md` — the bar for every file in this repository
