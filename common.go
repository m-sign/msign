package msign

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const (
	PrefixSIG = "SIG:" // signature prefix
	PrefixPUB = "PUB:" // public key prefix
	PrefixKEY = "KEY:" // private key prefix
)

const (
	VersionOne = 1 // msign version 1
)

const (
	sizeVersion = 1 // version size in bytes
)

var (
	ErrInvalidPubFormat = errors.New("invalid public key format")
	ErrInvalidSigFormat = errors.New("invalid signature format")
	ErrInvalidKeyFormat = errors.New("invalid private key format")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrKeyIdMismatch    = errors.New("invalid signature (key id mismatch)")
	ErrUnknownType      = errors.New("unknown export type")
	ErrNilWriter        = errors.New("nil writer")
	ErrNilReader        = errors.New("nil reader")
)

func NewPrivateKey() (PrivateKey, PublicKey, error) {
	return newPrivateKeyV1()
}

func (k KeyId) String() string {
	return hex.EncodeToString(k)
}

func ImportPublicKey(r io.Reader) (PublicKey, error) {
	if r == nil {
		return nil, ErrNilReader
	}

	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(line, PrefixPUB) {
		return nil, ErrInvalidPubFormat
	}

	line = strings.TrimPrefix(line, PrefixPUB) // remove prefix
	bd := base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(line))
	pub, err := io.ReadAll(bd)
	if err != nil {
		return nil, err
	}

	if len(pub) > sizeVersion {
		if pub[0] == VersionOne {
			return getPublicKeyV1(pub)
		}
	}

	return nil, ErrInvalidPubFormat
}

func ImportPrivateKey(r io.Reader) (PrivateKey, error) {
	if r == nil {
		return nil, ErrNilReader
	}

	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(line, PrefixKEY) {
		return nil, ErrInvalidKeyFormat
	}

	line = strings.TrimPrefix(line, PrefixKEY) // remove prefix
	bd := base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(line))
	key, err := io.ReadAll(bd)
	if err != nil {
		return nil, err
	}

	if len(key) > sizeVersion {
		if key[0] == VersionOne {
			return getPrivateKeyV1(key)
		}
	}

	return nil, ErrInvalidKeyFormat
}

func ImportSignature(r io.Reader) (Signature, error) {
	if r == nil {
		return nil, ErrNilReader
	}

	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(line, PrefixSIG) {
		return nil, ErrInvalidSigFormat
	}

	line = strings.TrimPrefix(line, PrefixSIG) // remove prefix
	bd := base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(line))
	sig, err := io.ReadAll(bd)
	if err != nil {
		return nil, err
	}

	if len(sig) > sizeVersion {
		if sig[0] == VersionOne {
			return getSignatureV1(sig)
		}
	}

	return nil, ErrInvalidSigFormat
}

func Export(w io.Writer, item any) error {
	if w == nil {
		return ErrNilWriter
	}

	switch i := item.(type) {
	case PublicKey:
		return i.export(w)
	case PrivateKey:
		return i.export(w)
	case Signature:
		return i.export(w)
	}

	return ErrUnknownType
}
