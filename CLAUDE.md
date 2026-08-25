# CLAUDE.md

This repository is a starter for developers outside the organisation. Everything committed here
is read by them as-is.

## The bar for every committed file

- **Client-presentable.** Code, comments, README, tests, commit messages: written for an outside
  developer integrating "Sign in with reZEN". If it would need explaining to them, rewrite it or
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

## Skills

Three Claude Code skills live under `.claude/skills/` in this repository, for anyone — reviewer or
integrator — working with a checkout that has Claude Code available.

- **`pr-review`** — reviews a pull request against this repository's samples: client-side
  protocol correctness, the twin-verifier invariant between the two samples' `id_token`
  verifiers, secret and token handling, and the repository bar above. Invoke as
  `/pr-review <PR URL> [--comment]`.
- **`review-integration`** — reviews an outside client's "Sign in with reZEN" implementation
  against the matching sample and reports a divergence table. Invoke as
  `/review-integration <path>`.
- **`build-integration`** — builds a new "Sign in with reZEN" integration in another project,
  in that project's own stack, using the samples' exchanges as the template. Invoke as
  `/build-integration <path>`.

Every file these skills produce is held to the same bar as every other file in this repository.
