# proton-cli local fork fix contract

## Reference revisions

- `roman-16/proton-cli`: `b8f4a4f816498c311134eb13515b19ab78107edf` (2026-08-07)
- `ProtonMail/WebClients`: `b42394a71e7f342a4825c42c083b612ecedd1f27` (2026-08-07)
- `protonpass/pass-cli`: `6253f7a42a59efcd7bbd484cf40cc0541933eb4f` (2026-08-05)
- `ProtonDriveApps/sdk`: `941aafa55fb179c8ee347c9d0b4660a3fc893f09` (2026-07-31)

## Confirmed fixes

### 1. Keep a Proton Pass item key and its rotation together

The current code encrypts updated content with the key from the fetched item revision. It then fetches `/key/latest`, ignores the returned key and any request error, and sends only the latest rotation. A key rotation between the item revision and the latest-key request can therefore label ciphertext with the wrong rotation.

The official Proton Pass CLI fetches the item revision, opens the key for that revision, encrypts with that key, and sends the revision's `KeyRotation`. The Web client instead fetches and opens the latest item key, but it also uses that same key for encryption and for `KeyRotation`. Both clients preserve the invariant.

Fix:

- Remove the unused `/key/latest` request from `ItemEdit`.
- Send `r.Item.KeyRotation`, which identifies the key used for encryption.
- Propagate Base64 and protobuf encoding errors instead of discarding them.

Tests:

- The update request uses the fetched revision rotation.
- No latest-key request occurs.
- Updated content decrypts with the fetched item key.
- Invalid Base64 input stops before PUT.

### 2. Make Proton Pass vault rename fail closed and use the latest vault key

The current code replaces a vault with an empty protobuf when existing content cannot be decrypted. It also re-encrypts with the content's old key rotation.

The official Proton Pass CLI requires content, propagates decryption and parsing errors, preserves all existing fields, fetches the latest share key, and encrypts the updated vault with that key and rotation.

Fix:

- Require existing vault content.
- Propagate decrypt and protobuf errors.
- Preserve the complete decoded vault object and change only its name.
- Fetch and use the latest available share key for new ciphertext.

Tests:

- Decryption failure causes no PUT.
- Description and unknown protobuf fields survive rename.
- Rename uses the highest available key rotation.

### 3. Enforce Proton Drive download integrity

The current code ignores share and node signature failures. It also downloads blocks without checking their indexes, encrypted SHA-256 hashes, or the revision manifest signature.

The official Drive SDK checks every encrypted block against its API SHA-256 hash. It concatenates the decoded hashes in manifest order and verifies the revision manifest signature with the revision author's public key, or the node key for anonymous content. It does not verify `EncSignature`; that field is deprecated. The official clients also report node metadata authorship before download.

Fix:

- Decode `Hash`, `ManifestSignature`, `SignatureEmail`, and thumbnail hashes from revision responses.
- Require continuous block indexes starting at 1.
- Verify each downloaded encrypted block against its API SHA-256 hash before decryption.
- Build the manifest from thumbnail hashes followed by regular block hashes, in API order.
- Verify the manifest before writing file content.
- Verify node and content-key metadata with the correct author key where the protocol supplies a signature.
- Do not add `EncSignature` verification because Proton has deprecated it.
- Stop on integrity failure. Do not expose an end-user bypass.

Tests:

- Valid multi-page download succeeds.
- A missing, repeated, or out-of-order index fails before block output.
- A block hash mismatch fails.
- A missing, invalid, or wrong-author manifest signature fails.
- Anonymous content verifies with the node key.
- Existing valid upload fixtures still download.

### 4. Stop Calendar updates when old event data cannot be decrypted

The current update helper converts any decryption error into empty event fields. `EventUpdate` then signs and writes those fields as the preserved title, location, description, recurrence, and organizer.

The official Calendar client requires a successful event read result before it creates an edit action. Card decryption throws when the session key, data, or required signature is missing.

Fix:

- Return a decryption error separately from the signature verdict.
- Keep read/list presentation behavior explicit.
- Require successful decryption in `EventUpdate` before any PUT.
- Preserve the decrypted recurrence and organizer only after that check.

Tests:

- Malformed cards and bad key packets cause no PUT.
- A valid but unverified card remains visible with its verdict.
- A valid update preserves fields that the user did not change.

### 5. Make raw API dry runs real dry runs

This is a proton-cli contract issue. Proton's clients have no equivalent raw command. The repository states that `--dry-run` applies to every mutating command, but raw POST, PUT, PATCH, and DELETE requests ignore it.

Fix:

- Classify GET, HEAD, and OPTIONS as read-only.
- Under `--dry-run`, do not send other methods. Render a dry-run result that names the method and endpoint.
- Keep normal raw requests unchanged. The raw command remains an explicit expert interface.

Tests:

- Mutating methods make no request under `--dry-run`.
- Read-only methods still run under `--dry-run`.
- Normal mutating requests still run when dry-run is absent.

### 6. Validate profile names at the CLI/config boundary

This is local proton-cli behavior. Proton's open-source clients do not use this profile-to-filename design. The current profile string can escape the session and ID-cache directories through path separators or `..` components.

Fix:

- Parse the profile once in `app.New` before any path or profile-scoped environment lookup.
- Accept a small portable set: ASCII letters, digits, `_`, `-`, and `.`, with a maximum length.
- Reject empty components, `.` and `..`, path separators, and names that do not start with an alphanumeric character.
- Use the validated profile value for sessions, ID cache, and profile-scoped environment variables.
- Add a second containment check in the file-path constructor as defense at the filesystem boundary.

Tests:

- Normal names such as `default`, `work`, and `my-work.2` pass.
- Traversal, absolute paths, separators, control characters, and overlong names fail before file access.
- `profiles delete` applies the same validator to every reference.

### 7. Stream mbox exports

This is a proton-cli-only feature. Proton's Web client exports one message at a time. The current mbox exporter retains all messages and attachments in one byte slice.

Fix:

- Add a destination writer that uses a temporary file and atomic rename for file output.
- Write each mbox entry as it is produced.
- Remove a temporary file when any message fails.
- Stream directly for stdout and return the first error.

Tests:

- Multiple entries are in the correct order.
- A later export error leaves no final file.
- Memory use does not grow with total archive size beyond one message.

### 8. Harden the release path used by the local fork

This is repository supply-chain behavior, not a Proton protocol rule.

Fix:

- Pin third-party GitHub Actions to full commit hashes.
- Remove `continue-on-error` from the primary release build.
- Make release verification compare asset digests or provenance, not names only.
- Add an independent signature for checksums before enabling self-update in the fork.
- Until signed updates exist, install the local fork from a locally built binary and do not use self-update.

Tests:

- The release workflow fails when the build step fails.
- The local installation path does not call self-update.

### 9. Generate Calendar and Contact UIDs from cryptographic randomness

The offline gate proved that two immediate `time.Now().UnixNano()` calls can
return the same value on a supported system. This can give two events the same
UID. The same clock-resolution defect affects Contact UIDs.

The official Calendar client generates 21 bytes with
`crypto.getRandomValues`, encodes them with unpadded Base64URL, and adds its
Calendar domain. The official Contacts code also creates a random UUID-shaped
value when a vCard has no UID.

Fix:

- Generate CLI event and contact UIDs from `crypto/rand` instead of wall-clock
  time.
- Keep the existing `@proton-cli` suffix for CLI-created event identity.

Tests:

- Immediate calls return different UIDs.
- Generated event UIDs keep the `@proton-cli` suffix.
- Generated contact UIDs keep the `proton-cli-` prefix.

## Audit items not changed after Proton source comparison

### Contact-card read failures during pinned-key lookup

The official Web client also catches contact-card lookup or decode errors and returns an empty pinned-key set. Its public-key model does not carry the helper error into send selection. A stricter fail-closed policy can be safer, but it is not confirmed Proton client behavior. Do not change it in this fork without a separate product decision and interoperability tests.

### Mail export fallback after body decryption failure

The official Web client deliberately puts the stored encrypted body into the export MIME document when its message state has a decryption error. The current CLI matches that behavior. Do not change it as a protocol correction. A future explicit warning is a user-interface improvement, not a source-confirmed compatibility fix.

### Deprecated Drive block `EncSignature`

The official Drive SDK explicitly does not verify per-block signatures and plans to remove them. Integrity comes from each encrypted block hash and the signed manifest. Do not implement `EncSignature` verification.

## Validation gate

- Focused tests for every changed boundary.
- `go test ./cmd/... ./internal/... -count=1`
- `go test -race ./cmd/... ./internal/... -count=1`
- `go vet ./cmd/... ./internal/...`
- `govulncheck ./...`
- Build the release-form local binary.
- Use no live Proton account until all offline tests pass.
- For live proof, use a dedicated test account and test fixtures. Never use the primary account first.
