# Agent Guidelines

## Project Context

This is an open-source CLI tool used by other people. All changes should consider:
- **Backwards compatibility** - consider impact on existing users when changing command syntax or flags, but don't let it block improvements
- **Cross-platform** - must work on Linux, macOS, and Windows (amd64 + arm64)
- **User-facing quality** - README, help text, and error messages should be clear and helpful
- **Distribution** - binaries are published as GitHub Releases via GoReleaser; users install by downloading a binary or via `go install`

## Feature Scope

proton-cli mirrors what the **Proton web clients let a user do**, not every endpoint the API exposes. If an action isn't something a user can do in the official web UI, don't add it to the CLI - even when a backend endpoint for it exists. Web-client parity beats API completeness.

## The interface is a language, and it is declared

proton-cli has one grammar, one verb per idea, and one shape per response. All of it is declared in code and checked by `internal/cli/conformance_test.go`, which walks the whole command tree. **Read `internal/cli/kit/lang.go` before adding a command.**

- `proton-cli <app> <collection> <verb> [TARGET…] [--flags]`. A group never acts.
- Verbs come from `kit.Verbs`. A word not in there is a word being invented.
- Argument names come from `kit.Placeholders`. `REF` is a full ID, a short ID, or a human handle; Drive uses `PATH` for things that exist in the tree.
- A flag name means exactly one thing CLI-wide. New shared flags go in `flagMeanings` in the conformance test, which fails if two commands disagree.
- Output goes through `internal/ui`: `kit.List`, `kit.Show`, `kit.Read`, `kit.Mutate`, `kit.Create`. Nothing outside `internal/ui` touches a process stream, and only `internal/app/credentials.go` reads a credential from a human.
- Mutations go through `kit.Mutate` or `kit.Create`, which is what makes `--dry-run` structural rather than remembered.
- Anything judgeable from the command line alone must be judged before the network: use `kit.Enum`, `kit.Color`, or cobra's `Args` and `MarkFlagRequired`.
- Selection uses `kit.Select`. Never write a second bulk-filter implementation.
- `internal/ui` has golden tests. Change a response and run `just golden`, then read the diff - it is the review.

## Quality Gates

For code changes, use the applicable gates below. Fix failures caused by the
change and rerun affected checks without asking at each step. Report unrelated
failures separately. Documentation-only edits need document checks unless they
change generated command documentation or release configuration.

1. **Fast tests** - `just test-fast` runs the unit, golden and conformance suites with no credentials and no network. It is the gate that catches an inconsistency.
2. **Lint** - **run `just lint` for code or configuration changes** and fix findings caused by the change. Report unrelated findings separately. It runs `gofmt -w .` and `golangci-lint run ./...` (CGO-free, so no C compiler needed).
3. **Build** - `just build` produces the release-shaped binary (`-tags=embed_hv` + the CGO webview helper); it needs the toolchain from `devbox shell`.
4. **Integration tests** - **do not run.** The suite hits the live Proton API, creates real data, and takes several minutes; the user runs it manually and reports back. See [Testing](#testing).

## Testing

Tests are **integration tests** that run against the live Proton API. They require `PROTON_USER` and `PROTON_PASSWORD` environment variables.

- **`just test-fast` is always safe** - no API, no credentials, seconds to run
- **Never run the full test suite** (`just test` / `go test ./tests/...`) - only the user triggers that manually
- **Single integration tests are allowed** (`just test-one TestName`) when verifying a specific change
- **`just docs`** regenerates `docs/commands/README.md` from the tree; CI fails on a diff
- **Unit test file naming**: name a unit test file after the source file it tests, with `_test.go` appended (e.g. `size.go` → `size_test.go`) - never after a symbol or after a file that doesn't exist. The integration tests under `tests/` are the exception: they are grouped by feature area.

## Reference Source

The Proton WebClients TypeScript source is available at `/tmp/proton-cli-WebClients/` (cloned from https://github.com/ProtonMail/WebClients). Use it as the primary reference for:

- API endpoint signatures, request/response shapes (`packages/shared/lib/api/`)
- Encryption flows and key handling (`packages/shared/lib/keys/`, `packages/crypto/`)
- How the web client calls endpoints (parameter names, types, ordering)
- Constants and enums (`packages/shared/lib/constants.ts`, etc.)

If the clone is missing or stale, run:
```bash
cd /tmp && git clone --depth 1 --branch main https://github.com/ProtonMail/WebClients.git proton-cli-WebClients
```
