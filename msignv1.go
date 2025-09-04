package msign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"io"
)

// msign version 1 implementation

const (
	sizeIDv1    = 6 // key id size in bytes
	sizeCheckv1 = 6 // validation block size in bytes
)

type privateKeyV1 struct {
	id    [sizeIDv1]byte
	bytes [ed25519.PrivateKeySize]byte
}

func (p *privateKeyV1) Sign(message io.Reader) (Signature, error) {
	if message == nil {
		return nil, ErrNilReader
	}

	sha512 := sha512.New()
	_, err := io.Copy(sha512, message)
	if err != nil {
		return nil, err
	}

	sigbytes := ed25519.Sign(ed25519.PrivateKey(p.bytes[:]), sha512.Sum(nil))
	sig := &signatureV1{}
	copy(sig.id[:], p.id[:])
	copy(sig.bytes[:], sigbytes)

	return sig, nil
}

func (p *privateKeyV1) Id() KeyId {
	id := make(KeyId, sizeIDv1)
	copy(id, p.id[:])
	return id
}

func (p *privateKeyV1) Public() PublicKey {
	pub := &publicKeyV1{}
	copy(pub.id[:], p.id[:])
	copy(pub.bytes[:], p.bytes[32:]) // see https://golang.org/pkg/crypto/ed25519/#PrivateKey (Public() method)
	return pub
}

func (p *privateKeyV1) export(w io.Writer) error {
	_, err := w.Write([]byte(PrefixKEY))
	if err != nil {
		return err
	}

	be := base64.NewEncoder(base64.RawURLEncoding, w)

	var priv [sizeVersion + sizeCheckv1 + sizeIDv1 + ed25519.PrivateKeySize]byte
	priv[0] = VersionOne                                      // version
	copy(priv[sizeVersion+sizeCheckv1:], p.id[:])             // copy id
	copy(priv[sizeVersion+sizeCheckv1+sizeIDv1:], p.bytes[:]) // copy private key

	check := sha256.Sum256(priv[sizeVersion+sizeCheckv1:])
	copy(priv[sizeVersion:], check[:sizeCheckv1]) // copy check

	_, err = be.Write(priv[:])
	if err != nil {
		return err
	}

	err = be.Close()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte("\n"))
	return err
}

type publicKeyV1 struct {
	id    [sizeIDv1]byte
	bytes [ed25519.PublicKeySize]byte
}

func (p *publicKeyV1) Verify(message io.Reader, sign Signature) (bool, error) {
	if message == nil {
		return false, ErrNilReader
	}

	sig, ok := sign.(*signatureV1)
	if !ok {
		return false, ErrInvalidSignature
	}

	if !bytes.Equal(p.id[:], sig.id[:]) {
		return false, ErrKeyIdMismatch
	}

	sha512 := sha512.New()
	_, err := io.Copy(sha512, message)
	if err != nil {
		return false, err
	}

	return ed25519.Verify(ed25519.PublicKey(p.bytes[:]), sha512.Sum(nil), sig.bytes[:]), nil
}

func (p *publicKeyV1) Id() KeyId {
	id := make(KeyId, sizeIDv1)
	copy(id, p.id[:])
	return id
}

func (p *publicKeyV1) export(w io.Writer) error {
	_, err := w.Write([]byte(PrefixPUB))
	if err != nil {
		return err
	}

	be := base64.NewEncoder(base64.RawURLEncoding, w)

	var pub [sizeVersion + sizeIDv1 + ed25519.PublicKeySize]byte
	pub[0] = VersionOne                // version
	copy(pub[1:], p.id[:])             // copy id
	copy(pub[1+sizeIDv1:], p.bytes[:]) // copy public key

	_, err = be.Write(pub[:])
	if err != nil {
		return err
	}

	err = be.Close()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte("\n"))
	return err
}

type signatureV1 struct {
	id    [sizeIDv1]byte
	bytes [ed25519.SignatureSize]byte
}

func (s *signatureV1) KeyId() KeyId {
	id := make(KeyId, sizeIDv1)
	copy(id, s.id[:])
	return id
}

func (s *signatureV1) export(w io.Writer) error {
	_, err := w.Write([]byte(PrefixSIG))
	if err != nil {
		return err
	}

	be := base64.NewEncoder(base64.RawURLEncoding, w)

	var sigmsg [sizeVersion + sizeCheckv1 + sizeIDv1 + ed25519.SignatureSize]byte
	sigmsg[0] = VersionOne // version

	copy(sigmsg[sizeVersion+sizeCheckv1:], s.id[:])             // copy id
	copy(sigmsg[sizeVersion+sizeCheckv1+sizeIDv1:], s.bytes[:]) // copy signature

	check := sha256.Sum256(sigmsg[sizeVersion+sizeCheckv1:])
	copy(sigmsg[sizeVersion:], check[:sizeCheckv1]) // copy check

	_, err = be.Write(sigmsg[:])
	if err != nil {
		return err
	}

	err = be.Close()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte("\n"))
	return err
}

// utility functions
func getPublicKeyV1(pub []byte) (PublicKey, error) {
	if len(pub) < sizeVersion+sizeCheckv1+ed25519.PublicKeySize {
		return nil, ErrInvalidPubFormat
	}

	if pub[0] != VersionOne {
		return nil, ErrInvalidPubFormat
	}

	publicKey := &publicKeyV1{}
	copy(publicKey.id[:], pub[1:1+sizeIDv1])
	copy(publicKey.bytes[:], pub[1+sizeIDv1:])

	// check
	check := sha256.Sum256(pub[sizeVersion+sizeCheckv1:])
	if !bytes.Equal(check[:sizeCheckv1], pub[sizeVersion:sizeVersion+sizeCheckv1]) {
		return nil, ErrInvalidKeyFormat
	}

	return publicKey, nil
}

func getPrivateKeyV1(priv []byte) (PrivateKey, error) {
	if len(priv) < sizeVersion+sizeCheckv1+sizeIDv1+ed25519.PrivateKeySize {
		return nil, ErrInvalidKeyFormat
	}

	if priv[0] != VersionOne {
		return nil, ErrInvalidKeyFormat
	}

	privateKey := &privateKeyV1{}
	copy(privateKey.id[:], priv[sizeVersion+sizeCheckv1:sizeVersion+sizeCheckv1+sizeIDv1])
	copy(privateKey.bytes[:], priv[sizeVersion+sizeCheckv1+sizeIDv1:])

	// check
	check := sha256.Sum256(priv[sizeVersion+sizeCheckv1:])
	if !bytes.Equal(check[:sizeCheckv1], priv[sizeVersion:sizeVersion+sizeCheckv1]) {
		return nil, ErrInvalidKeyFormat
	}

	return privateKey, nil
}

func getSignatureV1(sign []byte) (Signature, error) {
	if len(sign) < sizeVersion+sizeCheckv1+sizeIDv1+ed25519.SignatureSize {
		return nil, ErrInvalidSigFormat
	}

	if sign[0] != VersionOne {
		return nil, ErrInvalidSigFormat
	}

	signature := &signatureV1{}
	copy(signature.id[:], sign[sizeVersion+sizeCheckv1:sizeVersion+sizeCheckv1+sizeIDv1])
	copy(signature.bytes[:], sign[sizeVersion+sizeCheckv1+sizeIDv1:])

	// check
	check := sha256.Sum256(sign[sizeVersion+sizeCheckv1:])
	if !bytes.Equal(check[:sizeCheckv1], sign[sizeVersion:sizeVersion+sizeCheckv1]) {
		return nil, ErrInvalidSigFormat
	}

	return signature, nil
}

func newPrivateKeyV1() (PrivateKey, PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	id := sha256.Sum256(pub[:])
	privateKey := &privateKeyV1{}
	copy(privateKey.id[:], id[:sizeIDv1])
	copy(privateKey.bytes[:], priv)

	publicKey := &publicKeyV1{}
	copy(publicKey.id[:], id[:sizeIDv1])
	copy(publicKey.bytes[:], pub)

	return privateKey, publicKey, nil
}

// Sanity check types implement the interfaces
var (
	_ PublicKey  = &publicKeyV1{}
	_ PrivateKey = &privateKeyV1{}
	_ Signature  = &signatureV1{}
)
