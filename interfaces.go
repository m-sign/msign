package msign

import (
	"encoding/hex"
	"io"
)

// KeyID identifies a key pair. In format v1 it is the first 6 bytes of the
// SHA-256 hash of the public key.
//
// A KeyID is only a hint for picking the right public key. It is too short to
// prove identity: trust must be anchored on the complete public key.
type KeyID []byte

// String returns the KeyID as lowercase hex.
func (id KeyID) String() string {
	return hex.EncodeToString(id)
}

// Item is a PrivateKey, PublicKey or Signature: a value with an m-sign text
// encoding that can be written with Export.
//
// Item has only unexported methods, so it cannot be implemented outside this
// package.
type Item interface {
	appendText(dst []byte) []byte
}

// PrivateKey is an m-sign private key.
//
// Formatting a PrivateKey with the fmt package never prints key material; it
// prints only "msign.PrivateKey(<key id>)". Use Export to write the key.
type PrivateKey interface {
	Item

	// ID returns the KeyID of the key pair.
	ID() KeyID

	// Public returns the matching public key.
	Public() PublicKey

	// Sign reads message until EOF and returns its signature. The message is
	// streamed, so it can be of any size.
	Sign(message io.Reader) (Signature, error)
}

// PublicKey is an m-sign public key.
type PublicKey interface {
	Item

	// ID returns the KeyID of the key pair.
	ID() KeyID

	// Verify reads message until EOF and reports whether sig is a valid
	// signature of it by this key. It returns nil if the signature is valid.
	//
	// If the signature is invalid, the error matches ErrInvalidSignature.
	// If sig was made by a different key, the error is ErrKeyIDMismatch,
	// which also matches ErrInvalidSignature; in that case message is not
	// read. A nil message returns ErrNilReader, and an error reading message
	// is returned wrapped.
	Verify(message io.Reader, sig Signature) error

	// String returns the "PUB:" text encoding without the trailing newline.
	String() string
}

// Signature is a detached m-sign signature.
type Signature interface {
	Item

	// KeyID returns the KeyID of the key that made the signature.
	KeyID() KeyID

	// String returns the "SIG:" text encoding without the trailing newline.
	String() string
}
