// Package msign implements the m-sign key and signature formats.
//
// m-sign signs files with Ed25519 and stores private keys, public keys and
// detached signatures as single-line text items:
//
//	KEY:<base64url>   private key (77-byte payload, 108-byte line)
//	PUB:<base64url>   public key  (39-byte payload, 57-byte line)
//	SIG:<base64url>   signature   (77-byte payload, 108-byte line)
//
// The formats are specified in the m-sign data formats specification,
// version 1.0.0: https://github.com/m-sign/specs/blob/v1.0.0/format.md.
// This package implements format version 1 and reproduces the published
// test vectors.
//
// # Signing
//
// A signature is the Ed25519 signature (RFC 8032, PureEdDSA) of the 64-byte
// SHA-512 digest of the message. This is not Ed25519ph. Messages are read
// from an io.Reader and hashed as a stream, so files of any size can be
// signed and verified in constant memory.
//
// # Parsing
//
// Import functions read exactly one line and never read past its newline, so
// several items can be read from one stream. Parse functions take a string.
// Both accept LF, CRLF or no terminator, and reject anything that is not the
// canonical encoding of a valid item. Parse errors match ErrInvalidKeyFormat,
// ErrInvalidPubFormat or ErrInvalidSigFormat with errors.Is.
//
// # Security notes
//
//   - A KeyID is 48 bits. It helps pick the right public key but does not
//     prove identity: always verify against a public key you trust.
//   - Private keys are stored in plaintext. Protect "KEY:" files and
//     variables with file permissions or a secret manager, and never commit
//     them. Formatting a PrivateKey with fmt prints only its KeyID.
//   - Importing a private key checks that its public half matches its seed.
//   - A signature covers only the message bytes, not a file name or version.
//     To bind those, sign a manifest that contains them.
//
// All values returned by this package are immutable and safe for concurrent use.
package msign
