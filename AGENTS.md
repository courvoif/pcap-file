# Repository instructions

## Coding practices

* Keep code simple, readable, and DRY.
* Do not over-engineer or introduce unnecessary abstractions.
* Prefer small, focused functions and clear control flow.
* Space code into readable logical blocks.

### Rust structure

Each logical section of a Rust file must start with:

`/* ----- Description of the section ----- */`

Example:

`/* ----- Configuration ----- */`

Use section headers for meaningful groups such as imports, constants, types, configuration, helpers, core logic, tests, and similar areas.

### Comments

* In multi-sentence comments, put each sentence on a new line.
* Comment large, complex, or non-obvious code blocks.
* Explain intent, constraints, or reasoning rather than restating the code.
* Avoid comments for code that is already self-explanatory.
* Keep comments accurate when behavior changes.

Example:

```rust
// Validate the configuration before starting the worker.
// This prevents partially initialized state from being exposed.
validate_config(&config)?;
```

---

## Commits

Use Conventional Commits:

`<type>(<scope>): <description>`

Allowed types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `build`, `ci`.

Rules:

* Describe the intent and outcome, not just the implementation.
* Use imperative wording.
* Keep the subject concise.
* Use the body only when useful.
* Use bullet points in the body.
* Group bullets by short themes when multiple concerns exist.
* Do not invent motivations or behavior not supported by the diff.
* Order by importance.

Example:

`fix(auth): prevent expired sessions from being restored`

Validation:

* Reject expired sessions before restoring auth state.
* Clear stale session data when refresh fails.

State:

* Preserve the existing flow for valid sessions.

### Breaking changes

For breaking changes:

* Add `!` before `:`.
* Add a `BREAKING CHANGE:` footer explaining impact and migration.

Example:

`feat(api)!: remove legacy user endpoint`

API:

* Remove the deprecated `/v1/users` endpoint.

BREAKING CHANGE: Clients must migrate to `/v2/users`.

---

## Reviews

Review changes for correctness, consistency, maintainability, and completeness.

Check:

### Code

* Logic is valid and matches the intended behavior.
* Edge cases and failure paths are handled.
* No obvious regressions, dead code, duplication, or unnecessary complexity.
* Public APIs and contracts remain consistent unless intentionally changed.
* Breaking changes are identified.
* Error handling is appropriate.
* Security-sensitive changes do not introduce obvious vulnerabilities.
* Performance is reasonable for the affected path.
* Concurrency, state, and resource management are safe where relevant.
* Code follows the coding practices defined above.
* Abstractions are justified and do not over-engineer the solution.
* Repeated logic is consolidated where doing so improves clarity.

### Tests

* New behavior is covered where appropriate.
* Existing tests still reflect the intended behavior.
* Important edge cases and regressions are tested.
* Tests validate behavior rather than implementation details where possible.
* Tests are concise.

### Documentation

* Documentation matches the actual behavior.
* Public APIs, configuration, examples, and setup instructions are updated when needed.
* Deprecated or removed behavior is not still documented as supported.
* Breaking changes and migrations are documented.

### Consistency

* Naming, patterns, architecture, and style match the surrounding codebase.
* Implementation and documentation do not contradict each other.
* Configuration, types, schemas, and API definitions remain synchronized.
* Similar features behave consistently.

### Scope

* The change solves the stated problem without unrelated modifications.
* Suspicious or accidental changes are called out.
* Large unrelated concerns should be split when appropriate.

### Review output

Prioritize findings by severity:

* `critical` — security issue, data loss, major correctness problem, or severe regression
* `high` — likely bug or breaking behavior
* `medium` — maintainability, inconsistency, missing validation, or meaningful documentation/test gap
* `low` — minor improvement or cleanup

For each finding:

* Explain the problem.
* Explain the impact.
* Point to the relevant code or behavior.
* Suggest a concrete fix when possible.

Do not report speculative issues without evidence.
Do not focus on formatting unless it affects correctness or violates repository conventions.
If no meaningful issues are found, say so explicitly.

---

## Changelog

When updating the changelog:

* Describe user-visible or developer-visible changes only.
* Group entries under: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
* Keep entries concise and outcome-focused.
* Exclude internal refactors, tests, CI, and implementation details unless they affect users or consumers.
* Mention breaking changes explicitly.
* Include migration instructions when applicable.
* Do not duplicate the commit message verbatim if a clearer changelog description is possible.
