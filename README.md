# github.com/m-sign/msign
[![License][license-img]][license] [![Actions Status][action-img]][action] [![PkgGoDev][pkggodev-img]][pkggodev] [![Go Report Card][goreport-img]][goreport] [![Coverage Status][codecov-img]][codecov]

## Overview
This repository contains the Go implementation of the m-sign signature formats.

m-sign signs files with Ed25519 and stores keys and signatures as single-line text items, such as `PUB:AThuQYp3…`, that are easy to keep in files, environment variables and CI secrets. The formats are defined in the [m-sign data formats specification](https://github.com/m-sign/specs/blob/v1.0.0/format.md), and this package reproduces its [test vectors](testdata/vectors-v1.json).

For a command-line tool, see [m-sign/tools](https://github.com/m-sign/tools).

## Installation
```bash
go get github.com/m-sign/msign@v1
```

The package uses only the Go standard library. It supports the two most recent Go releases.

## Usage
```go
priv, pub, err := msign.NewPrivateKey()
if err != nil {
	return err
}

f, err := os.Open("release.tar.gz")
if err != nil {
	return err
}
defer f.Close()

sig, err := priv.Sign(f) // the file is streamed, not loaded into memory
if err != nil {
	return err
}
if err := msign.Export(os.Stdout, sig); err != nil { // SIG:...
	return err
}

// Later, with the public key from a trusted source:
pub, err = msign.ParsePublicKey(os.Getenv("MSIGN_PUBLIC"))
if err != nil {
	return err
}
f2, err := os.Open("release.tar.gz")
if err != nil {
	return err
}
defer f2.Close()
if err := pub.Verify(f2, sig); err != nil {
	// errors.Is(err, msign.ErrInvalidSignature) reports an invalid signature,
	// or one made by another key; other errors come from reading the file.
	return err
}
```

See the [package documentation][pkggodev] for the full API and examples.

## Security notes
- A KeyID is only 48 bits. It helps choose a public key but does not prove identity: always verify against a public key you trust.
- `KEY:` items are plaintext private keys. Protect them with file permissions (`0600`) or a secret manager, and never commit them. Printing a `PrivateKey` with `fmt` shows only its KeyID.
- A signature covers only the bytes of the message, not the file name or a version. To bind those, sign a manifest that contains them.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Stability
The module follows semantic versioning. The v1 API is stable, and the v1 byte format is frozen: keys and signatures created by any version stay valid.

## Migrating from v0.1.0
| v0.1.0 | v1.0.0 |
|---|---|
| `KeyId` | `KeyID` |
| `.Id()` | `.ID()` |
| `ErrKeyIdMismatch` | `ErrKeyIDMismatch` (also matches `ErrInvalidSignature`) |
| `ErrUknownType` | `ErrUnknownType` |
| `ok, err := pub.Verify(r, sig)` | `err := pub.Verify(r, sig)`: `nil` means valid |
| `Export(w, any)` | `Export(w, msign.Item)` |
| — | `ParsePrivateKey`, `ParsePublicKey`, `ParseSignature`, `ErrUnsupportedVersion`, `PublicKey.String()`, `Signature.String()` |

Parsing is stricter in v1. Inputs that v0.1.0 accepted but the specification forbids are now rejected; see the [changelog](CHANGELOG.md).

## Contributing
We encourage and support an active, healthy community of contributors &mdash;
including you! Details are in the [contribution guide](CONTRIBUTING.md) and
the [code of conduct](CODE_OF_CONDUCT.md).

[![Contributor Covenant][covenant-img]](CODE_OF_CONDUCT.md)

[covenant-img]: https://img.shields.io/badge/contributor%20covenant-v2.1%20adopted-ff69b4.svg
[license-img]: https://img.shields.io/badge/license-MIT-blue.svg
[license]: LICENSE
[action-img]: https://github.com/m-sign/msign/actions/workflows/go-test.yaml/badge.svg
[action]: https://github.com/m-sign/msign/actions/workflows/go-test.yaml
[goreport-img]: https://goreportcard.com/badge/github.com/m-sign/msign
[goreport]: https://goreportcard.com/report/github.com/m-sign/msign
[codecov-img]: https://codecov.io/gh/m-sign/msign/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/m-sign/msign
[pkggodev-img]: https://pkg.go.dev/badge/github.com/m-sign/msign
[pkggodev]: https://pkg.go.dev/github.com/m-sign/msign
