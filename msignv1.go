package msign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// msign version 1 implementation

const (
	sizeIDv1    = 6 // key id size in bytes
	sizeCheckv1 = 6 // validation block size in bytes

	offsetCheckV1 = sizeVersion                 // start of Check in private key and signature payloads
	offsetBodyV1  = offsetCheckV1 + sizeCheckv1 // start of the bytes covered by Check

	sizeKeyV1 = offsetBodyV1 + sizeIDv1 + ed25519.PrivateKeySize // private key payload: 77 bytes
	sizePubV1 = sizeVersion + sizeIDv1 + ed25519.PublicKeySize   // public key payload: 39 bytes
	sizeSigV1 = offsetBodyV1 + sizeIDv1 + ed25519.SignatureSize  // signature payload: 77 bytes
)

type privateKeyV1 struct {
	id    [sizeIDv1]byte
	bytes [ed25519.PrivateKeySize]byte // seed || public key
}

func (p *privateKeyV1) Sign(message io.Reader) (Signature, error) {
	if message == nil {
		return nil, ErrNilReader
	}

	sha512 := sha512.New()
	_, err := io.Copy(sha512, message)
	if err != nil {
		return nil, fmt.Errorf("msign: reading message: %w", err)
	}

	sigbytes := ed25519.Sign(ed25519.PrivateKey(p.bytes[:]), sha512.Sum(nil))
	sig := &signatureV1{}
	copy(sig.id[:], p.id[:])
	copy(sig.bytes[:], sigbytes)

	return sig, nil
}

func (p *privateKeyV1) ID() KeyID {
	id := make(KeyID, sizeIDv1)
	copy(id, p.id[:])
	return id
}

func (p *privateKeyV1) Public() PublicKey {
	pub := &publicKeyV1{}
	copy(pub.id[:], p.id[:])
	copy(pub.bytes[:], p.bytes[ed25519.SeedSize:]) // see https://golang.org/pkg/crypto/ed25519/#PrivateKey (Public() method)
	return pub
}

// String returns a redacted description of the key.
func (p *privateKeyV1) String() string {
	return "msign.PrivateKey(" + hex.EncodeToString(p.id[:]) + ")"
}

// Format prints the redacted description for every verb, so that key
// material never reaches logs through the fmt package.
func (p *privateKeyV1) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, p.String())
}

func (p *privateKeyV1) appendText(dst []byte) []byte {
	var priv [sizeKeyV1]byte
	priv[0] = VersionOne                            // version
	copy(priv[offsetBodyV1:], p.id[:])              // copy id
	copy(priv[offsetBodyV1+sizeIDv1:], p.bytes[:])  // copy private key
	check := sha256.Sum256(priv[offsetBodyV1:])     // check covers everything after itself
	copy(priv[offsetCheckV1:], check[:sizeCheckv1]) // copy check
	return appendItem(dst, PrefixKEY, priv[:])
}

type publicKeyV1 struct {
	id    [sizeIDv1]byte
	bytes [ed25519.PublicKeySize]byte
}

func (p *publicKeyV1) Verify(message io.Reader, sign Signature) error {
	if message == nil {
		return ErrNilReader
	}

	sig, ok := sign.(*signatureV1)
	if !ok || sig == nil {
		return ErrInvalidSignature
	}

	if !bytes.Equal(p.id[:], sig.id[:]) {
		return ErrKeyIDMismatch
	}

	sha512 := sha512.New()
	_, err := io.Copy(sha512, message)
	if err != nil {
		return fmt.Errorf("msign: reading message: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(p.bytes[:]), sha512.Sum(nil), sig.bytes[:]) {
		return ErrInvalidSignature
	}
	return nil
}

func (p *publicKeyV1) ID() KeyID {
	id := make(KeyID, sizeIDv1)
	copy(id, p.id[:])
	return id
}

func (p *publicKeyV1) String() string {
	return string(p.appendText(nil))
}

func (p *publicKeyV1) appendText(dst []byte) []byte {
	var pub [sizePubV1]byte
	pub[0] = VersionOne                          // version
	copy(pub[sizeVersion:], p.id[:])             // copy id
	copy(pub[sizeVersion+sizeIDv1:], p.bytes[:]) // copy public key
	return appendItem(dst, PrefixPUB, pub[:])
}

type signatureV1 struct {
	id    [sizeIDv1]byte
	bytes [ed25519.SignatureSize]byte
}

func (s *signatureV1) KeyID() KeyID {
	id := make(KeyID, sizeIDv1)
	copy(id, s.id[:])
	return id
}

func (s *signatureV1) String() string {
	return string(s.appendText(nil))
}

func (s *signatureV1) appendText(dst []byte) []byte {
	var sigmsg [sizeSigV1]byte
	sigmsg[0] = VersionOne                            // version
	copy(sigmsg[offsetBodyV1:], s.id[:])              // copy id
	copy(sigmsg[offsetBodyV1+sizeIDv1:], s.bytes[:])  // copy signature
	check := sha256.Sum256(sigmsg[offsetBodyV1:])     // check covers everything after itself
	copy(sigmsg[offsetCheckV1:], check[:sizeCheckv1]) // copy check
	return appendItem(dst, PrefixSIG, sigmsg[:])
}

// utility functions

func appendItem(dst []byte, prefix string, payload []byte) []byte {
	dst = append(dst, prefix...)
	return base64.RawURLEncoding.AppendEncode(dst, payload)
}

// keyIDv1 returns the v1 KeyID of an Ed25519 public key.
func keyIDv1(pub []byte) [sizeIDv1]byte {
	sum := sha256.Sum256(pub)
	var id [sizeIDv1]byte
	copy(id[:], sum[:sizeIDv1])
	return id
}

// validCheckV1 reports whether the Check field of a private key or signature
// payload matches the bytes it covers.
func validCheckV1(payload []byte) bool {
	check := sha256.Sum256(payload[offsetBodyV1:])
	return subtle.ConstantTimeCompare(check[:sizeCheckv1], payload[offsetCheckV1:offsetBodyV1]) == 1
}

// getPublicKeyV1 parses a v1 public key payload: version || id || public key.
func getPublicKeyV1(pub []byte) (PublicKey, error) {
	if len(pub) != sizePubV1 {
		return nil, fmt.Errorf("%w: payload is %d bytes, want %d", ErrInvalidPubFormat, len(pub), sizePubV1)
	}

	publicKey := &publicKeyV1{}
	copy(publicKey.id[:], pub[sizeVersion:sizeVersion+sizeIDv1])
	copy(publicKey.bytes[:], pub[sizeVersion+sizeIDv1:])

	if keyIDv1(publicKey.bytes[:]) != publicKey.id {
		return nil, fmt.Errorf("%w: key id does not match the public key", ErrInvalidPubFormat)
	}

	return publicKey, nil
}

// getPrivateKeyV1 parses a v1 private key payload:
// version || check || id || seed || public key.
func getPrivateKeyV1(priv []byte) (PrivateKey, error) {
	if len(priv) != sizeKeyV1 {
		return nil, fmt.Errorf("%w: payload is %d bytes, want %d", ErrInvalidKeyFormat, len(priv), sizeKeyV1)
	}

	if !validCheckV1(priv) {
		return nil, fmt.Errorf("%w: check mismatch", ErrInvalidKeyFormat)
	}

	privateKey := &privateKeyV1{}
	copy(privateKey.id[:], priv[offsetBodyV1:offsetBodyV1+sizeIDv1])
	copy(privateKey.bytes[:], priv[offsetBodyV1+sizeIDv1:])

	seed := privateKey.bytes[:ed25519.SeedSize]
	pub := privateKey.bytes[ed25519.SeedSize:]
	if keyIDv1(pub) != privateKey.id {
		return nil, fmt.Errorf("%w: key id does not match the public key", ErrInvalidKeyFormat)
	}

	// A public half that does not belong to the seed must never be used for
	// signing: signatures under two public keys can leak the secret scalar.
	if subtle.ConstantTimeCompare(ed25519.NewKeyFromSeed(seed), privateKey.bytes[:]) != 1 {
		return nil, fmt.Errorf("%w: public key does not match the seed", ErrInvalidKeyFormat)
	}

	return privateKey, nil
}

// getSignatureV1 parses a v1 signature payload: version || check || id || signature.
func getSignatureV1(sign []byte) (Signature, error) {
	if len(sign) != sizeSigV1 {
		return nil, fmt.Errorf("%w: payload is %d bytes, want %d", ErrInvalidSigFormat, len(sign), sizeSigV1)
	}

	if !validCheckV1(sign) {
		return nil, fmt.Errorf("%w: check mismatch", ErrInvalidSigFormat)
	}

	signature := &signatureV1{}
	copy(signature.id[:], sign[offsetBodyV1:offsetBodyV1+sizeIDv1])
	copy(signature.bytes[:], sign[offsetBodyV1+sizeIDv1:])

	return signature, nil
}

func newPrivateKeyV1() (PrivateKey, PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	id := keyIDv1(pub)
	privateKey := &privateKeyV1{id: id}
	copy(privateKey.bytes[:], priv)

	publicKey := &publicKeyV1{id: id}
	copy(publicKey.bytes[:], pub)

	return privateKey, publicKey, nil
}

// Sanity check types implement the interfaces
var (
	_ PublicKey     = &publicKeyV1{}
	_ PrivateKey    = &privateKeyV1{}
	_ Signature     = &signatureV1{}
	_ fmt.Formatter = &privateKeyV1{}
)
