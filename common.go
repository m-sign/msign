package msign

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Prefixes of the text encodings.
const (
	PrefixSIG = "SIG:" // signature prefix
	PrefixPUB = "PUB:" // public key prefix
	PrefixKEY = "KEY:" // private key prefix
)

// VersionOne is the version byte of the v1 formats.
const VersionOne = 1

const (
	sizeVersion   = 1    // version size in bytes
	maxLineLength = 1024 // longest item line accepted by the readers, terminator excluded
)

// Errors returned by this package. Parse errors wrap ErrInvalidKeyFormat,
// ErrInvalidPubFormat or ErrInvalidSigFormat; compare them with errors.Is.
var (
	// ErrInvalidPubFormat is matched by every error from parsing a public key.
	ErrInvalidPubFormat = errors.New("invalid public key format")
	// ErrInvalidSigFormat is matched by every error from parsing a signature.
	ErrInvalidSigFormat = errors.New("invalid signature format")
	// ErrInvalidKeyFormat is matched by every error from parsing a private key.
	ErrInvalidKeyFormat = errors.New("invalid private key format")
	// ErrUnsupportedVersion is matched, together with the format error of
	// the item type, when an item has a version this package does not know.
	ErrUnsupportedVersion = errors.New("unsupported version")
	// ErrInvalidSignature is returned by PublicKey.Verify for an invalid signature.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrKeyIDMismatch is returned by PublicKey.Verify when the signature was
	// made by a different key. It matches ErrInvalidSignature.
	ErrKeyIDMismatch = fmt.Errorf("%w (key id mismatch)", ErrInvalidSignature)
	// ErrUnknownType is returned by Export for a nil item.
	ErrUnknownType = errors.New("unknown export type")
	// ErrNilWriter is returned when a nil io.Writer is passed.
	ErrNilWriter = errors.New("nil writer")
	// ErrNilReader is returned when a nil io.Reader is passed.
	ErrNilReader = errors.New("nil reader")
)

// NewPrivateKey generates a new key pair using crypto/rand.
func NewPrivateKey() (PrivateKey, PublicKey, error) {
	return newPrivateKeyV1()
}

// ImportPublicKey reads one "PUB:" line from r and parses it.
//
// It reads exactly one line and never reads past its newline, so further
// items can be read from the same reader. A CRLF terminator and a missing
// terminator at the end of input are accepted.
func ImportPublicKey(r io.Reader) (PublicKey, error) {
	line, err := readLine(r, ErrInvalidPubFormat)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(line)
}

// ImportPrivateKey reads one "KEY:" line from r and parses it.
// It reads like ImportPublicKey.
func ImportPrivateKey(r io.Reader) (PrivateKey, error) {
	line, err := readLine(r, ErrInvalidKeyFormat)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(line)
}

// ImportSignature reads one "SIG:" line from r and parses it.
// It reads like ImportPublicKey.
func ImportSignature(r io.Reader) (Signature, error) {
	line, err := readLine(r, ErrInvalidSigFormat)
	if err != nil {
		return nil, err
	}
	return parseSignature(line)
}

// ParsePublicKey parses a "PUB:" item. One trailing LF or CRLF is optional.
func ParsePublicKey(s string) (PublicKey, error) {
	line, err := trimLine(s, ErrInvalidPubFormat)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(line)
}

// ParsePrivateKey parses a "KEY:" item. One trailing LF or CRLF is optional.
func ParsePrivateKey(s string) (PrivateKey, error) {
	line, err := trimLine(s, ErrInvalidKeyFormat)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(line)
}

// ParseSignature parses a "SIG:" item. One trailing LF or CRLF is optional.
func ParseSignature(s string) (Signature, error) {
	line, err := trimLine(s, ErrInvalidSigFormat)
	if err != nil {
		return nil, err
	}
	return parseSignature(line)
}

// Export writes the text encoding of item, followed by a newline, to w in a
// single Write call.
func Export(w io.Writer, item Item) error {
	if w == nil {
		return ErrNilWriter
	}
	if item == nil {
		return ErrUnknownType
	}

	_, err := w.Write(append(item.appendText(nil), '\n'))
	return err
}

func parsePublicKey(line string) (PublicKey, error) {
	payload, err := decodeItem(line, PrefixPUB, ErrInvalidPubFormat)
	if err != nil {
		return nil, err
	}
	return getPublicKeyV1(payload)
}

func parsePrivateKey(line string) (PrivateKey, error) {
	payload, err := decodeItem(line, PrefixKEY, ErrInvalidKeyFormat)
	if err != nil {
		return nil, err
	}
	return getPrivateKeyV1(payload)
}

func parseSignature(line string) (Signature, error) {
	payload, err := decodeItem(line, PrefixSIG, ErrInvalidSigFormat)
	if err != nil {
		return nil, err
	}
	return getSignatureV1(payload)
}

// decodeItem checks the prefix and the base64 text of line and returns the
// payload. The payload has at least the version byte, and the version is
// known; the version-specific parser checks the rest.
func decodeItem(line, prefix string, errFormat error) ([]byte, error) {
	data, ok := strings.CutPrefix(line, prefix)
	if !ok {
		return nil, fmt.Errorf("%w: missing %q prefix", errFormat, prefix)
	}

	// The base64 decoder skips CR and LF, so check the alphabet first.
	for i := 0; i < len(data); i++ {
		if !isBase64URLChar(data[i]) {
			return nil, fmt.Errorf("%w: invalid character at offset %d", errFormat, len(prefix)+i)
		}
	}

	payload, err := base64.RawURLEncoding.Strict().DecodeString(data)
	if err != nil || len(payload) < sizeVersion {
		return nil, fmt.Errorf("%w: invalid base64 encoding", errFormat)
	}

	if payload[0] != VersionOne {
		return nil, fmt.Errorf("%w: %w %d", errFormat, ErrUnsupportedVersion, payload[0])
	}
	return payload, nil
}

func isBase64URLChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// trimLine removes one trailing LF or CRLF from s. Any other LF is an error.
func trimLine(s string, errFormat error) (string, error) {
	if line, ok := strings.CutSuffix(s, "\n"); ok {
		s = strings.TrimSuffix(line, "\r")
	}
	if strings.Contains(s, "\n") {
		return "", fmt.Errorf("%w: more than one line", errFormat)
	}
	return s, nil
}

// readLine reads one item line from r without reading past its LF. It
// returns the line without its LF or CRLF terminator. End of input after at
// least one byte also ends the line.
func readLine(r io.Reader, errFormat error) (string, error) {
	if r == nil {
		return "", ErrNilReader
	}

	br, ok := r.(io.ByteReader)
	if !ok {
		br = byteReader{r}
	}

	var line []byte
	for {
		c, err := br.ReadByte()
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return "", fmt.Errorf("%w: empty input", errFormat)
			}
			return string(line), nil
		}
		if err != nil {
			return "", fmt.Errorf("msign: reading item: %w", err)
		}

		if c == '\n' {
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			return string(line), nil
		}

		if len(line) >= maxLineLength {
			return "", fmt.Errorf("%w: line longer than %d bytes", errFormat, maxLineLength)
		}
		line = append(line, c)
	}
}

// byteReader reads one byte at a time from a reader that is not an
// io.ByteReader, so that nothing is read past the end of the line.
type byteReader struct {
	r io.Reader
}

func (b byteReader) ReadByte() (byte, error) {
	var buf [1]byte
	_, err := io.ReadFull(b.r, buf[:])
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return buf[0], err
}
