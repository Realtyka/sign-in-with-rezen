---
name: pr-review
description: Code review a pull request against this repository's samples. Checks client-side OAuth 2.1 / OIDC protocol correctness (discovery-driven endpoints, PKCE, state/nonce, RS256-only id_token verification), that the two samples' identity-token verifiers stay identical, that no secret or token ever reaches a log, a URL, or a fixture, and that every file still meets this repository's client-presentable bar.
allowed-tools: Bash(gh issue view:*), Bash(gh search:*), Bash(gh issue list:*), Bash(gh pr comment:*), Bash(gh pr diff:*), Bash(gh pr view:*), Bash(gh pr list:*), Bash(gh api:*), Bash(git rev-parse:*), Bash(git log:*), Read, Glob, Grep, Write, Task, TaskCreate, TaskUpdate, TaskGet, TaskList
argument-hint: "<PR_URL> [--comment]"
---

# PR Review Pipeline

Provide a code review for the given pull request, focused on this repository: two runnable,
zero-dependency samples of "Sign in with reZEN" — the OAuth 2.1 authorization code flow with PKCE
and OpenID Connect identity — one server-side (`confidential-client/`), one browser-only
(`public-client/`). Both are read by outside developers as reference implementations. Review them
like the security-sensitive, client-presentable surface they are.

---

## STEP 0: Parse Arguments

Extract `owner`, `repo`, and `pr_number` from `$ARGUMENTS`. Also check if `--comment` flag is present.

- **`--comment` flag**: When present, post the review directly to the PR as inline comments + summary comment.
- **Default (no flag)**: Write the review to `pr-review-{pr_number}.md` as a local file.

Supported PR URL formats:
- `https://github.com/{owner}/{repo}/pull/{number}`
- `https://github.com/{owner}/{repo}/pull/{number}/files`
- `{owner}/{repo}#{number}`
- `{owner}/{repo}/pull/{number}`

If the format is unrecognized, stop and ask the user for a valid PR URL.

---

**Agent assumptions (applies to all agents and subagents):**
- All tools are functional and will work without error. Do not test tools or make exploratory calls.
- Only call a tool if it is required to complete the task. Every tool call should have a clear purpose.

To do this, follow these steps precisely:

## STEP 1: Pre-flight Check

Launch a haiku agent to check if any of the following are true:
   - The pull request is closed
   - The pull request is a draft
   - The pull request does not need code review (e.g. automated release PR, trivial version bump)

   If any condition is true, stop and do not proceed.

Note: Still review Claude-generated PRs. Re-reviews on the same PR are allowed — do not skip a PR just because Claude has previously commented on it.

## STEP 2: Gather PR Data & Context

Launch three agents in parallel:

   Agent A (haiku): Return a list of file paths (not their contents) for all relevant guideline files:
   - The root `CLAUDE.md` file (the repository's bar for every committed file)
   - The root `README.md` and, if either sample changed, that sample's own `README.md`
   - `test-vectors/id-token.json` if either `oidc.js` file changed
   - **If `.github/workflows/` files changed**: include every changed workflow plus one unchanged workflow for convention comparison (there may be none yet — that is not an error)

   Agent B (haiku): Fetch existing review comments on this PR using `gh pr view <PR> --comments` and `gh api repos/{owner}/{repo}/pulls/{pr_number}/comments`. Return a list of existing inline comments with their file path, line number, and a brief summary of the comment content. This will be used for deduplication later.

   Agent C (haiku): Gather PR metadata and file-level context:
   1. Fetch PR metadata: title, author, description, base/head branches, additions/deletions, state, file list with per-file change stats using `gh pr view` and `gh pr diff --stat`.
   2. For each file in the PR diff that has **more than 30 lines changed**, fetch the **full file** from the PR's head branch (using `gh api repos/{owner}/{repo}/contents/{path}?ref={head_branch}` or reading from the local checkout). **Limit to the top 10 most-changed files.**
   3. Return all metadata and full file contents.

## STEP 3: Summarize Changes

Launch a sonnet agent to view the pull request and return a structured summary of the changes.

The summary must include:

**Section 1 — "## Summary"**
Write a 2-4 sentence executive summary of what this PR does and why. Categorize the PR as one or more of: Feature, Bugfix, Refactor, Configuration, CI, Test, Documentation.

If the PR changes >500 lines or >15 files, add a warning:
> **Large PR Warning**: This PR modifies {X} files with {Y} total line changes. Consider splitting into smaller, focused PRs for easier review.

**Section 2 — "## Key Changes"**
List the most important changes grouped by category. For each key change:
- Use a ### subheading with the category and a short description
- Write 1-2 sentences explaining what changed
- Include a **syntax-highlighted code snippet** (```js, ```json, etc.) showing the most relevant new/changed code (5-20 lines max per snippet)
- Below the snippet, add: `> [{filename}]({pr_url}/files#diff-{file_anchor})` linking to the file in the PR

Focus on the **most impactful** changes. Aim for 3-7 key changes, not an exhaustive list.

## STEP 4: Parallel Review Agents

Launch 4 agents in parallel to independently review the changes.

Each agent receives the PR title, description, diff, per-file change stats, full file contents for heavily-changed files (from Step 2 Agent C), and relevant guideline files (from Step 2 Agent A).

Each agent must return findings in this structured format:

   ```
   FILE: <exact file path>
   LINE: <line number or range>
   SEVERITY: CRITICAL | HIGH | MEDIUM
   CATEGORY: <e.g., "protocol correctness", "twin-verifier drift", "secret exposure", "repository bar">
   ISSUE: <brief description>
   EVIDENCE: <code snippet or trace proving the issue>
   SUGGESTION: <how to fix>
   ```

   The agents should do the following:

   **Agent 1: Protocol Correctness of the Client Side (Sonnet)**

   Audit protocol-surface changes for correctness against the exchanges either sample performs.
   Both samples read every endpoint from the issuer's discovery document (`discover()` in each
   `oidc.js`) — nothing hardcodes an endpoint path. Check:
   - **Discovery-driven endpoints** — any new or changed call to an OAuth/OIDC endpoint that
     hardcodes a URL instead of reading it from the discovery document is HIGH.
   - **PKCE** — the challenge method must stay S256 (`pkce()` in each `oidc.js`); anything that
     drops PKCE, weakens it to `plain`, or reuses a verifier across requests is CRITICAL.
   - **`state` and `nonce`** — must be freshly generated per authorization request and checked on
     return before anything else in the response is trusted (the public sample checks `state`
     before even looking at an `error` parameter, so a crafted callback URL cannot spoof an
     error page for a flow it didn't start — see `public-client/public/callback.js`). Skipping or
     weakening either check is CRITICAL.
   - **`response_type=code`** — the only grant either sample uses; anything introducing an
     implicit or hybrid response type is CRITICAL.
   - **Token exchange client authentication** — the confidential sample sends HTTP Basic with
     RFC 6749 §2.3.1 form-encoding of both `client_id` and `client_secret` (`formEncode()`,
     `exchangeCode()` in `confidential-client/src/oidc.js`) whenever a secret is configured, and
     falls back to `client_id` in the body only when there is none; the public sample always sends
     `client_id` in the body and never a secret or an `Authorization` header
     (`public-client/public/oidc.js`). A change that sends a secret from the public sample, or
     that drops Basic auth from the confidential sample when a secret is configured, is CRITICAL.
   - **`id_token` verification** — RS256 only (the algorithm in the header is never trusted to
     choose itself), with `iss`, `aud` (including the `azp` rule when `aud` has more than one
     value), `exp`/`iat` with the fixed clock-skew leeway, and `nonce` all checked — see the
     Twin-Verifier Invariant agent below for the additional cross-sample requirement.
   - **`/userinfo`** — the only place either sample sends `Authorization: Bearer`
     (`userinfo()` in each `oidc.js`); a Bearer header anywhere else is HIGH.
   - **API calls** — the access token travels as `x-api-key`, never `Authorization: Bearer`
     (`apiCall()` in each `oidc.js`); reversing that is HIGH.
   - **Revocation (RFC 7009)** — the token goes in the POST body, never a URL or a log line
     (`revoke()` in each `oidc.js`); treating a non-200 or a 200 response as proof a token did or
     did not exist is a misunderstanding of RFC 7009 §2.2 (revocation is idempotent and must not
     become an oracle) and is MEDIUM.

   In addition, note any **positive observations** — correct discovery use, clean PKCE handling.

   **Agent 2: Twin-Verifier Invariant (Sonnet)**

   `confidential-client/src/oidc.js` and `public-client/public/oidc.js` each carry their own
   `verifyIdToken()` — one against Node's `crypto` module, one against the browser's Web Crypto
   API — and the repository's contract is that the two stay identical in what they accept, what
   they reject, and what they say when they reject. `test-vectors/id-token.json` is the shared
   vector both samples' test suites run through their own copy for exactly this reason. Check:
   - Any change to one `verifyIdToken()` (a new check, a relaxed check, a changed error message,
     a changed clock-skew constant) without the identical change to the other is HIGH.
   - Any change to `test-vectors/id-token.json`, or to either sample's use of it, that does not
     keep both `npm test` suites passing is HIGH — the PR diff and CI results are the source of
     truth; if CI hasn't run, say so rather than guessing.
   - A new invalid-token case added to one sample's test file without the matching case in the
     other (or without it living in the shared vector) is MEDIUM — it lets the two verifiers drift
     unnoticed.

   In addition, note any **positive observations** — a vector case added to both suites at once, a
   change landed symmetrically.

   **Agent 3: Secrets & Token Handling (Sonnet)**

   Check every changed file, including tests, fixtures, and comments:
   - **No secret, token, or key in committed content** — placeholders only. A real-looking
     credential anywhere (not just in `.env.example`, which must stay a placeholder) is CRITICAL.
   - **Tokens never in a URL or a log line** — a token interpolated into a query string, a
     `console.log`/`console.warn`/`console.error` call, or an error message that isn't already
     caught and stripped (see `disconnect()` in `public-client/public/app.js`, which never logs
     the token it just failed to revoke) is HIGH.
   - **Public client keeps the refresh token in memory only** — anything that writes it to
     `sessionStorage`, `localStorage`, a cookie, or anywhere else persistent is CRITICAL (see
     `public-client/README.md`'s "Where tokens live").
   - **Confidential client never sends the client secret to the browser** — a secret reaching a
     response body, a rendered page, or a client-visible header is CRITICAL.

   Self-validation: before reporting each finding, the agent must ask "Is this definitely a secret
   or token exposure a security engineer would flag?" If uncertain, discard.

   **Agent 4: Repository Bar (Sonnet)**

   This repository's `CLAUDE.md` sets the bar for every file in it: client-presentable, no
   internal references (no ticket identifiers, no internal project/tool/repository/service names,
   no people's names outside `.github/CODEOWNERS`, no internal hostnames — only the issuer and API
   hosts the vendor guide already publishes), no secrets, zero runtime dependencies, minimal,
   speaking the vendor guide's terminology. Check:
   - **`package.json` dependency changes** — any new `dependencies` entry (not `devDependencies` —
     there should be none of those either) in either sample's `package.json` is HIGH; the point of
     these samples is that they run on Node ≥ 18 built-ins alone.
   - **Internal references** — grep the diff for ticket-style identifiers, internal tool or
     service names, or hostnames that are not the published issuer/API hosts. Any hit is HIGH.
   - **Client-presentable prose** — a comment, README line, or error message that would need
     explaining to an outside developer is MEDIUM; suggest the rewrite.
   - **If `.github/workflows/` files appear in the diff** — this repository has none today; a new
     workflow is in scope for a normal review (pinned action SHAs, least-privilege
     `permissions:`, no secrets echoed into PR-controlled contexts) but is not itself a violation.

   In addition, note any **positive observations** — a file that reads clean against the bar.

   ---

   **CRITICAL: We only want HIGH SIGNAL issues.** Flag issues where:
   - PKCE, `state`/`nonce` checking, or token-exchange client authentication is weakened
   - The two `verifyIdToken()` implementations diverge in what they accept or reject
   - A secret, token, or key appears in committed content, a URL, or a log line
   - The public client persists a refresh token, or the confidential client leaks its secret
   - A runtime dependency is added to either sample's `package.json`
   - An internal reference (ticket id, internal tool/service name, internal hostname, a person's
     name outside CODEOWNERS) appears anywhere but `.github/CODEOWNERS`
   - Clear CLAUDE.md violations with the exact rule being broken

   Do NOT flag:
   - Code style or formatting preferences
   - Potential issues that depend on the issuer's or the API's own behavior
   - Subjective suggestions or improvements
   - Performance optimizations
   - Missing comments or docs on unchanged code
   - Pre-existing issues in unchanged code

   **Self-validation**: Before reporting each finding, the agent must ask itself: "Is this definitely real?" and "Would a senior engineer flag this?" If either answer is no, discard the finding.

   In addition to the above, each subagent should be told the PR title and description. This will help provide context regarding the author's intent.

## STEP 5: Validate Findings

For findings from Agent 1 (Protocol Correctness) and Agent 2 (Twin-Verifier Invariant), launch parallel sonnet subagents to validate each issue. These subagents receive the PR title, description, and a description of the finding. The agent's job is to review the issue and validate that it is truly an issue with high confidence.

Each validation subagent must classify the finding as:
- **CONFIRMED**: Issue is real and validated against the codebase
- **FALSE POSITIVE**: Issue is not real, with explanation why

Findings from Agent 3 (Secrets & Token Handling) and Agent 4 (Repository Bar) produce factual findings verifiable from the diff alone (e.g., "a dependency was added", "a hostname is not the published one") and do not need validation subagents.

## STEP 6: Filter & Deduplicate

Filter out any issues classified as FALSE POSITIVE in step 5. Deduplicate remaining issues: if multiple agents flagged the same issue (same file + nearby lines + same category), merge them into a single finding. This step gives us our list of high signal issues.

## STEP 7: Synthesize Report

Combine all agent outputs into a structured report.

### Report Structure

Build the report in this exact order:

```markdown
# Code Review: #{pr_number} — {title}

**Author:** {author} | **Branch:** `{head}` -> `{base}` | **Files:** {fileCount} | +{additions} / -{deletions}
**PR:** {link to PR}

---

{Step 3 output: Summary + Key Changes sections}

---

## Review Findings

{List of all validated issues found (if any), with:}
{- File path and line number(s)}
{- Description of the issue}
{- Severity: CRITICAL / HIGH / MEDIUM}
{- Category (e.g., "protocol correctness", "twin-verifier drift", "secret exposure", "repository bar")}
{- Evidence: code snippet or trace}
{- Suggested fix}

{If no issues were found, state: "No issues found. Checked for client-side protocol correctness, twin-verifier drift, secret and token handling, and the repository bar."}

---

## Positive Observations

{Things done well noted by any reviewer — clean discovery use, a vector added to both suites at once. If none noted, omit this section.}

---

## Action Items

{Consolidated checklist of ALL findings sorted by severity (CRITICAL first, then HIGH, MEDIUM). Merge duplicate findings. Format as GitHub task list checkboxes:}

- [ ] **[Critical]** _Category_ — Finding description (`file:line`) — Suggestion
- [ ] **[High]** _Category_ — Finding description (`file:line`) — Suggestion
- [ ] **[Medium]** _Category_ — Finding description (`file:line`) — Suggestion

{If no CRITICAL or HIGH findings: "No critical or high severity issues found."}

---

## Dropped Findings

{If any findings were dropped as false positives, list them with one-line explanations so the user can verify the reasoning. If none, omit this section.}

---

## Verdict

{Based on the aggregate findings:}
- If any [Critical] findings -> **Request Changes** with rationale
- If [High] findings but no [Critical] -> **Request Changes** or **Approve with Concerns** depending on count/nature
- If only [Medium] -> **Approve with Nits**
- If no findings -> **Approve**

**Verdict: {APPROVE | APPROVE WITH NITS | APPROVE WITH CONCERNS | REQUEST CHANGES}**
Critical: {N} | High: {N} | Medium: {N}
{One sentence rationale}
```

---

## STEP 8: Output the Report

### If `--comment` flag is NOT set (default):

Write the full report to `pr-review-{pr_number}.md` using the Write tool. After writing, inform the user of the file path and a 2-3 line summary of the verdict and key findings count.

Do not post any GitHub comments. Stop here.

### If `--comment` flag IS set and NO issues were found:

Post a summary comment using `gh pr comment <PR> --body "<message>"` with the format below and stop:

```
## Code Review: #{pr_number} — {title}

**Author:** {author} | **Files:** {fileCount} | +{additions} / -{deletions}

No issues found. Checked for client-side protocol correctness, twin-verifier drift, secret and token handling, and the repository bar.

## Verdict: APPROVE

Generated by Claude Code Review
```

### If `--comment` flag IS set and issues WERE found:

Continue with the following sub-steps:

**8a. Deduplicate against existing PR comments** (from Step 2 Agent B). For each issue, check if an existing inline comment already covers the same file path + nearby line number (within 3 lines) + similar topic. Remove any issues that are already covered. If all issues are already covered, post a summary comment noting no new issues and stop.

**8b. Create a list of all comments** that you plan on leaving. This is only for you to make sure you are comfortable with the comments. Do not post this list anywhere.

**8c. Post inline comments** as a single batched review using the GitHub API.

First get the head commit SHA:
```bash
gh pr view {pr_number} --repo {owner}/{repo} --json headRefOid --jq '.headRefOid'
```

Then submit all inline comments in a **single API call** using a heredoc with the complete JSON body:

   ```bash
   gh api repos/{owner}/{repo}/pulls/{pr_number}/reviews \
     --method POST \
     --input - <<'EOF'
   {
     "commit_id": "<head SHA>",
     "event": "COMMENT",
     "body": "<summary of all issues>",
     "comments": [
       {
         "path": "public-client/public/oidc.js",
         "line": 42,
         "side": "RIGHT",
         "body": "Comment body here"
       }
     ]
   }
   EOF
   ```

   For each inline comment body:
   ```
   **[Severity]** _Category_ — **Title**

   Description of the issue.

   **Evidence:** What's wrong and where
   **Fix:** How to resolve

   Claude Code Review
   ```

   - For small, self-contained fixes, include a committable suggestion block
   - For larger fixes, describe the issue and suggested fix without a suggestion block
   - Never post a committable suggestion UNLESS committing the suggestion fixes the issue entirely

   **IMPORTANT: Only post ONE comment per unique issue. Do not post duplicate comments.**

**8d. Post a summary PR comment** with the verdict, action items, and key highlights:

```bash
gh pr comment {pr_number} --repo {owner}/{repo} --body "$(cat <<'REVIEW_EOF'
## Code Review: #{pr_number} — {title}

**Author:** {author} | **Files:** {fileCount} | +{additions} / -{deletions}

Code review with **N Critical**, **N High**, and **N Medium** findings. See inline comments on specific lines for details.

### Summary
{Executive summary from Step 3}

### Action Items
{Consolidated checklist from all agents, sorted by severity:}
- [ ] **[Critical]** _Category_ — Finding description (`file`) — Suggestion
- [ ] **[High]** _Category_ — Finding description (`file`) — Suggestion
- [ ] **[Medium]** _Category_ — Finding description (`file`) — Suggestion

{If no Critical or High findings: "No critical or high severity issues found."}

### Positive Observations
{Things done well, noted by any reviewer. If none, omit.}

## Verdict: {APPROVE | APPROVE WITH NITS | APPROVE WITH CONCERNS | REQUEST CHANGES}
Critical: {N} | High: {N} | Medium: {N}
{One sentence rationale}

Generated by Claude Code Review
REVIEW_EOF
)"
```

---

## ERROR HANDLING

- If the PR URL cannot be parsed, ask the user for clarification
- If any `gh` CLI command fails, report the error and continue with available data
- If an agent fails, include a note in the relevant section: "Review could not be completed for this dimension."
- If the PR is in a merged/closed state, the pre-flight check in Step 1 will catch this

---

## FALSE POSITIVES

Use this list when evaluating issues in Steps 4 and 5 (these are false positives, do NOT flag):

- Pre-existing issues in unchanged code
- Issues that appear to be a bug but are actually correct given the context (e.g. the deliberate
  asymmetry between the two samples' revocation calls — see each README's "Sign out and
  Disconnect" note — is by design, not a bug)
- Pedantic nitpicks that a senior engineer would not flag
- Issues that `node --test` or the sample's own `npm test` would catch (do not run the suites to
  verify — CI or the reviewer does that)
- Refresh not being implemented — both samples say so explicitly and point at the vendor guide;
  flag it only if a PR claims to add refresh and gets it wrong
- Missing comments or type annotations on unchanged code

## Notes

- Use `gh` CLI for all GitHub interactions. Do not use web fetch.
- Create a todo list before starting.
- You must cite each issue in inline comments — if referring to a CLAUDE.md rule, a README
  convention, or a numbered RFC section already cited in the code, include that reference.
- When linking to code in inline comments, use: `https://github.com/owner/repo/blob/FULL_SHA/path/to/file.ext#L10-L15`
  - Requires full git SHA (not abbreviated)
  - Use `#` after file name, line range format `L[start]-L[end]`
  - Provide at least 1 line of context before and after
