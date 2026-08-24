# CLAUDE.md

This repository is a starter for developers outside the organisation. Everything committed here
is read by them as-is.

## The bar for every committed file

- **Client-presentable.** Code, comments, README, tests, commit messages: written for an outside
  developer integrating "Login with reZEN". If it would need explaining to them, rewrite it or
  leave it out.
- **No internal references.** No ticket identifiers, internal project or tool names, internal
  repository or service names, people's names, or internal hostnames. The only hostnames that
  belong here are the public issuer and the public API hosts that the integration guide already
  publishes.
- **No secrets, ever.** No client secrets, tokens, or keys — not in examples, not in tests, not in
  fixtures. Placeholders only (`cs_live_…`, `real_…`).
- **Zero runtime dependencies.** Node.js ≥ 18 built-ins only. Nothing to vet, nothing to update.
- **Minimal.** One page, one flow, the fewest files that show it working end to end. Nothing
  speculative.
- **Speak the guide's language.** Terminology and step order follow the vendor integration guide
  at `<issuer>/docs`. Link to it rather than restating it.

## Before committing

Read the diff as the outside developer would. If anything in it is not for them, it does not go in.
