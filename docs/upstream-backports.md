# Compatible upstream fixes

These changes were adapted from `roman-16/proton-cli` while keeping this fork's
command syntax and safety checks.

- [Session and key unlocking](https://github.com/roman-16/proton-cli/commit/a60f9552685a90697ea0b646922adbfe1fbdd4c1): discard the previous session's key blob on login, match the primary user key to its salt, support legacy unsalted keys, and seal the key password after the keys open.
- [Authentication errors](https://github.com/roman-16/proton-cli/commit/df29184): check HTTP failures before parsing JSON and report network failures with the documented exit code. The retry machinery from this commit is not included.
- [Prompts](https://github.com/roman-16/proton-cli/commit/d37e9da): use a label, colon and one space, and share one reader so answers typed ahead survive later prompts.
- [API output and auto-reply validation](https://github.com/roman-16/proton-cli/commit/349ac19): keep invalid JSON off stdout, accept an empty response, and validate an auto-reply schedule before reporting a dry run. This fork also skips sign-in for an auto-reply dry run.
- [Private file output](https://github.com/roman-16/proton-cli/commit/d1a8a90): write through a private temporary file and rename it into place. Replacing a readable file makes it private, and replacing a symbolic link leaves its target untouched.

Offline tests cover sign-in with and without two-factor authentication, key
unlocking and resuming a saved session, HTTP failures, prompts, file output,
and auto-reply dry runs. Live account integration tests remain manual.

Upstream's newer command grammar, contact parser, encryption architecture and
feature collection are not part of these backports.
