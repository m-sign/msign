# Changelog

All notable changes to this module are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - unreleased

The v1 byte format is unchanged: every key and signature created by v0.1.0 stays valid and re-exports byte for byte. The module now implements the [m-sign data formats specification 1.0.0](https://github.com/m-sign/specs/blob/v1.0.0/format.md) and passes its test vectors.

### Breaking
| v0.1.0 | v1.0.0 |
|---|---|
| `KeyId` | `KeyID` |
| `.Id()` | `.ID()` |
| `ErrKeyIdMismatch` | `ErrKeyIDMismatch` |
| `ErrUknownType` | `ErrUnknownType` |
| `ok, err := pub.Verify(r, sig)` | `err := pub.Verify(r, sig)`: `nil` means valid; failures match `ErrInvalidSignature` |
| `Export(w, any)` | `Export(w, msign.Item)` |

- Parse errors are wrapped: compare them with `errors.Is(err, ErrInvalidKeyFormat)` (or `ErrInvalidPubFormat`, `ErrInvalidSigFormat`) instead of `==`. Empty input and base64 errors no longer return bare `io.EOF` or `base64.CorruptInputError`.
- The minimum Go version is 1.26.

### Added
- `ParsePrivateKey`, `ParsePublicKey` and `ParseSignature` parse items from strings; the trailing newline is optional.
- `PublicKey.String()` and `Signature.String()` return the text encoding.
- `ErrUnsupportedVersion` for items with an unknown version byte.
- `Item`, the type accepted by `Export`.
- Package documentation, examples, fuzz tests, benchmarks, and tests against the specification's test vectors.

### Fixed
- Import functions no longer read ahead: they consume exactly one line, so several items can be read from one stream.
- Input lines are limited to 1024 bytes.
- A missing final newline and a CRLF terminator are accepted.
- Importing a public key with a KeyID mismatch returned `ErrInvalidKeyFormat`; it now returns `ErrInvalidPubFormat`.

### Security
- Importing a private key now checks that its KeyID matches its public key and that its public key matches its seed. A key with a tampered public half could leak the secret scalar when signing.
- Parsing rejects non-canonical input that v0.1.0 accepted: trailing bytes after the payload, non-canonical base64, and CR characters inside the data.
- Formatting a `PrivateKey` with `fmt` prints only `msign.PrivateKey(<key id>)` instead of the key bytes.
- Integrity checks on private keys use constant-time comparisons.

## [0.1.0] - 2023-11-19

- First release.
