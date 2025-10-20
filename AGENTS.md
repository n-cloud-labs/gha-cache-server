# Repository Contribution Instructions

Maintainer: Alessandro Chitolina <alekitto@gmail.com>

## Code formatting
- When your changes include source files (Rust sources, `Cargo.toml`, `Cargo.lock`, or comment-only edits), format the workspace with `cargo fmt --all` before committing.
- Run `cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features` whenever source files change.
- Skip formatting and the auto-fix clippy run if no source files are modified.
- Failing to format when required will cause CI failures.

## Cargo manifest style
- Apply these rules to every `Cargo.toml` in the workspace.
- List dependency entries in alphabetical order by crate name inside each `[dependencies]`, `[build-dependencies]`, `[dev-dependencies]`, `[workspace.dependencies]`, and `target.<triple>.dependencies` table.
- Declare dependencies using the explicit inline table form, for example `anyhow = { version = "1" }` instead of shorthand strings. Include all keys (such as `path`, `features`, and `default-features`) inside the inline table.
- Keep section ordering consistent across manifests:
  1. `[package]` metadata.
  2. Target configuration tables such as `[lib]`, `[[bin]]`, or similar (ordered alphabetically when multiple are present).
  3. General dependency tables (`[dependencies]` and any scoped variants like `[dependencies.<platform>]`).
  4. Build dependency tables.
  5. Dev dependency tables.
  6. Target-specific dependency tables (`[target.<triple>.dependencies]`, `[target.<triple>.dev-dependencies]`, etc.), sorted by target triple and following the same alphabetical rule within each table.
  7. Feature definitions.
  8. Any remaining metadata tables (for example `[package.metadata.*]`).
- Separate each table with a single blank line to keep manifests readable.

## Testing
- Execute `cargo test --all-targets --all-features` and `cargo clippy --all-targets --all-features` when your changes touch source files (including manifests, lockfiles, or comments).
- Skip these commands if no source code files are modified.
- Only trigger GitHub workflows when source files change.
- Ensure required tests pass before opening a PR.

## Documentation
- Write all documentation in English.
- Document new features as they are implemented; do not defer documentation updates to later changes.
- Always ensure the appropriate documentation files accompany repository additions.
- Follow the canonical documentation structure from `rust-guidelines.txt` for every public module and item. Each doc comment must
  start with a concise summary sentence, then include the relevant `# Examples`, `# Errors`, `# Panics`, or `# Safety` sections as
  required by the guidelines.

## Rust-specific guidelines
- Install `mimalloc` as the global allocator for binaries unless tests explicitly require the system allocator.
- Replace any `#[allow(...)]` attributes with `#[expect(..., reason = "…")]` and remove `#[allow(unfulfilled_lint_expectations)]`
  markers. Keep the reasons specific and meaningful.
- Each `unsafe` block must be justified with an adjacent `// SAFETY:` comment that explains how the invariants from
  `rust-guidelines.txt` are satisfied.
- Keep test helper modules behind `#[cfg(any(test, feature = "test-util"))]` gates so they are not exported by default.
- Treat `rust-guidelines.txt` as normative: new Rust code must be reviewed against its checklist before submission, and
  deviations require an explicit maintainer approval noted in the change description.

## Protocol stability
- Treat the public cache protocol as immutable. Do not modify `.proto` files or existing wire schemas.
- HTTP status codes, headers, and response payload shapes for public cache endpoints are part of the protocol. Do not change them without an explicit maintainer request.

## Domain and payload structures
- When an API request/response payload has the same shape as a domain model, keep a duplicated struct:
  - The payload type (with serialization, deserialization, and validation) lives in the API layer.
  - The domain type lives in the core crate and must not depend on serialization or validation attributes.
- Provide `From`/`TryFrom` implementations so callers can convert quickly between the payload and domain types.

## PR Guidance
- Provide a short summary of changes in the pull request description.
- Mention any modifications to the Helm chart or Dockerfile explicitly.
- Use descriptive English branch names.
- Follow the Conventional Commits specification for commit messages.
