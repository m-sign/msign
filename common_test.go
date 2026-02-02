package msign

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

// Good test vectors
const (
	testPrivateKey = "KEY:Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8\n"
	testPublicKey  = "PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf\n"
	testKeyID      = "386e418a77ca"
	testSignature  = "SIG:AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk\n"
)

// Bad test vectors
const (
	testBadPrivateKey_1 = "KEY:Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8"
	testBadPrivateKey_2 = "KEYAef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8\n"
	testBadPrivateKey_3 = "Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8\n"
	testBadPrivateKey_4 = "KEY:Baf8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8\n"
	testBadPrivateKey_5 = "KEY:Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8\n"

	testBadPublicKey_1 = "PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf"
	testBadPublicKey_2 = "PUBAThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf\n"
	testBadPublicKey_3 = "AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf\n"
	testBadPublicKey_4 = "PUB:BthuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf\n"
	testBadPublicKey_5 = "PUB:AThuQYp3ygaFaLSZ3PehpV8dil1tSfssC93ul3fbzFf\n"

	testBadSignature_1 = "SIG:AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk"
	testBadSignature_2 = "SIGAfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk\n"
	testBadSignature_3 = "AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk\n"
	testBadSignature_4 = "SIG:BcX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk\n"
	testBadSignature_5 = "SIG:AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk\n"
)

// helpers

func LimitWriter(w io.Writer, limit int64) io.Writer {
	return &LimitedWriter{W: w, N: limit, Err: ErrUnknownType}
}

type LimitedWriter struct {
	W   io.Writer // underlying writer
	N   int64     // max bytes remaining
	Err error     // error to be returned once limit is reached
}

func (lw *LimitedWriter) Write(p []byte) (int, error) {
	if lw.N < 1 {
		return 0, lw.Err
	}
	if lw.N < int64(len(p)) {
		p = p[:lw.N]
	}
	n, err := lw.W.Write(p)
	lw.N -= int64(n)
	return n, err
}

// Unittest for NewPrivateKey
func TestNewPrivateKey(t *testing.T) {
	_, _, err := NewPrivateKey()
	if err != nil {
		t.Errorf("NewPrivateKey() failed: %v", err)
	}
}

func TestWholeSigningProcess(t *testing.T) {
	// Generate a new key pair
	priv, pub, err := NewPrivateKey()
	if err != nil {
		t.Errorf("NewPrivateKey() failed: %v", err)
	}

	// Sign a message
	msg := []byte("Hello World!")
	sig, err := priv.Sign(bytes.NewReader(msg))
	if err != nil {
		t.Errorf("Sign() failed: %v", err)
	}

	// Verify the signature
	v, err := pub.Verify(bytes.NewReader(msg), sig)
	if err != nil {
		t.Errorf("Verify() failed: %v", err)
	}
	if !v {
		t.Errorf("Verify() failed: %v", err)
	}
	v, err = pub.Verify(bytes.NewReader(msg), nil)
	if err != ErrInvalidSignature {
		t.Errorf("Verify() failed: %v", err)
	}
	msg[0] = 'h' // change the message
	v, err = pub.Verify(bytes.NewReader(msg), sig)
	if err != nil {
		t.Errorf("Verify() failed: %v", err)
	}
	if v {
		t.Errorf("Verify() failed: %v", err)
	}

}

func TestWholeSigningProcess_Bad(t *testing.T) {
	// Generate a new key pair
	priv, pub, err := NewPrivateKey()
	if err != nil {
		t.Errorf("NewPrivateKey() failed: %v", err)
	}

	// Sign a message
	msg := []byte("Hello World!")
	sig, err := priv.Sign(nil)
	if err != ErrNilReader {
		t.Errorf("Sign() failed: %v", err)
	}

	sig, err = priv.Sign(iotest.ErrReader(ErrNilWriter))
	if err != ErrNilWriter {
		t.Errorf("Sign() failed: %v", err)
	}

	sig, err = priv.Sign(bytes.NewReader(msg))
	if err != nil {
		t.Errorf("Sign() failed: %v", err)
	}

	// Verify the signature
	v, err := pub.Verify(nil, sig)
	if err != ErrNilReader {
		t.Errorf("Verify() failed: %v", err)
	}
	v, err = pub.Verify(iotest.ErrReader(ErrNilReader), sig)
	if err != ErrNilReader {
		t.Errorf("Verify() failed: %v", err)
	}

	v, err = pub.Verify(bytes.NewReader(msg), sig)
	if err != nil {
		t.Errorf("Verify() failed: %v", err)
	}
	if !v {
		t.Errorf("Verify() failed: %v", err)
	}
}

func TestKeyId(t *testing.T) {
	// Generate a new key pair
	priv, pub, err := NewPrivateKey()
	if err != nil {
		t.Errorf("NewPrivateKey() failed: %v", err)
	}

	// Sign a message
	msg := []byte("Hello World!")
	sig, err := priv.Sign(bytes.NewReader(msg))
	if err != nil {
		t.Errorf("Sign() failed: %v", err)
	}

	// Check the key ID
	if bytes.Compare(pub.Id(), priv.Id()) != 0 {
		t.Errorf("KeyID() failed: %v", err)
	}

	if bytes.Compare(sig.KeyId(), pub.Id()) != 0 {
		t.Errorf("KeyID() failed: %v", err)
	}

	if sig.KeyId().String() != pub.Id().String() {
		t.Errorf("KeyID() failed: %v", err)
	}

}

func TestPublicKey(t *testing.T) {
	// Generate a new key pair
	priv, pub, err := NewPrivateKey()
	if err != nil {
		t.Errorf("NewPrivateKey() failed: %v", err)
	}

	pub2 := priv.Public()
	if !reflect.DeepEqual(pub, pub2) {
		t.Errorf("Public() keys are different: %v", pub)
	}
}

func TestPublicKey2(t *testing.T) {
	// Import a public key
	pub, err := ImportPublicKey(strings.NewReader(testPublicKey))
	if err != nil {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
	// Import a private key
	priv, err := ImportPrivateKey(strings.NewReader(testPrivateKey))
	if err != nil {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}

	// Check if the public key is the same
	pub2 := priv.Public()
	if !reflect.DeepEqual(pub, pub2) {
		t.Errorf("Public() keys are different: %v", pub)
	}
}

// Unittest for ImportPublicKey
func TestImportPublicKey(t *testing.T) {
	pub, err := ImportPublicKey(strings.NewReader(testPublicKey))
	if err != nil {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}

	if pub.Id().String() != testKeyID {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
}

func TestImportPublicKey_Bad(t *testing.T) {
	_, err := ImportPublicKey(strings.NewReader(testBadPublicKey_1))
	if err != io.EOF {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
	_, err = ImportPublicKey(strings.NewReader(testBadPublicKey_2))
	if err != ErrInvalidPubFormat {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
	_, err = ImportPublicKey(strings.NewReader(testBadPublicKey_3))
	if err != ErrInvalidPubFormat {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
	_, err = ImportPublicKey(strings.NewReader(testBadPublicKey_4))
	if err != ErrInvalidPubFormat {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
	_, err = ImportPublicKey(strings.NewReader(testBadPublicKey_5))
	if err != ErrInvalidPubFormat {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
	_, err = ImportPublicKey(nil)
	if err != ErrNilReader {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
	_, err = ImportPublicKey(iotest.ErrReader(io.EOF))
	if err != io.EOF {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}
}

// Unittest for ImportPrivateKey
func TestImportPrivateKey(t *testing.T) {
	priv, err := ImportPrivateKey(strings.NewReader(testPrivateKey))
	if err != nil {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}

	if priv.Id().String() != testKeyID {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}
}

func TestImportPrivateKey_Bad(t *testing.T) {
	_, err := ImportPrivateKey(strings.NewReader(testBadPrivateKey_1))
	if err != io.EOF {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}
	_, err = ImportPrivateKey(strings.NewReader(testBadPrivateKey_2))
	if err != ErrInvalidKeyFormat {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}
	_, err = ImportPrivateKey(strings.NewReader(testBadPrivateKey_3))
	if err != ErrInvalidKeyFormat {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}
	_, err = ImportPrivateKey(strings.NewReader(testBadPrivateKey_4))
	if err != ErrInvalidKeyFormat {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}
	_, err = ImportPrivateKey(strings.NewReader(testBadPrivateKey_5))
	if err != ErrInvalidKeyFormat {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}
	_, err = ImportPrivateKey(nil)
	if err != ErrNilReader {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}
	_, err = ImportPrivateKey(iotest.ErrReader(io.EOF))
	if err != io.EOF {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}

}

func TestImportSignature(t *testing.T) {
	sig, err := ImportSignature(strings.NewReader(testSignature))
	if err != nil {
		t.Errorf("ImportSignature() failed: %v", err)
	}

	if sig.KeyId().String() != testKeyID {
		t.Errorf("ImportSignature() failed: %v", err)
	}
}

func TestImportSignature_Bad(t *testing.T) {
	_, err := ImportSignature(strings.NewReader(testBadSignature_1))
	if err != io.EOF {
		t.Errorf("ImportSignature() failed: %v", err)
	}
	_, err = ImportSignature(strings.NewReader(testBadSignature_2))
	if err != ErrInvalidSigFormat {
		t.Errorf("ImportSignature() failed: %v", err)
	}
	_, err = ImportSignature(strings.NewReader(testBadSignature_3))
	if err != ErrInvalidSigFormat {
		t.Errorf("ImportSignature() failed: %v", err)
	}
	_, err = ImportSignature(strings.NewReader(testBadSignature_4))
	if err != ErrInvalidSigFormat {
		t.Errorf("ImportSignature() failed: %v", err)
	}
	_, err = ImportSignature(strings.NewReader(testBadSignature_5))
	if err != ErrInvalidSigFormat {
		t.Errorf("ImportSignature() failed: %v", err)
	}
	_, err = ImportSignature(nil)
	if err != ErrNilReader {
		t.Errorf("ImportSignature() failed: %v", err)
	}
	_, err = ImportSignature(iotest.ErrReader(io.EOF))
	if err != io.EOF {
		t.Errorf("ImportSignature() failed: %v", err)
	}

}

// Unittest for Export with public key
func TestExport_PublicKey(t *testing.T) {
	key, err := ImportPublicKey(strings.NewReader(testPublicKey))
	if err != nil {
		t.Errorf("ImportPublicKey() failed: %v", err)
	}

	buf := new(bytes.Buffer)
	err = Export(buf, key)
	if err != nil {
		t.Errorf("Export() with public key failed: %v", err)
	}

	if buf.String() != testPublicKey {
		t.Errorf("Export() with public key failed by value mismatch: %v", buf.String())
	}

	err = Export(LimitWriter(buf, 0), key)
	if err != ErrUnknownType {
		t.Errorf("Export() with public key failed: %v", err)
	}

	err = Export(LimitWriter(buf, 4), key)
	if err != ErrUnknownType {
		t.Errorf("Export() with public key failed: %v", err)
	}

	err = Export(LimitWriter(buf, 16), key)
	if err != ErrUnknownType {
		t.Errorf("Export() with public key failed: %v", err)
	}
}

// Unittest for Export with private key
func TestExport_PrivateKey(t *testing.T) {
	key, err := ImportPrivateKey(strings.NewReader(testPrivateKey))
	if err != nil {
		t.Errorf("ImportPrivateKey() failed: %v", err)
	}

	buf := new(bytes.Buffer)
	err = Export(buf, key)
	if err != nil {
		t.Errorf("Export() with private key failed: %v", err)
	}

	if buf.String() != testPrivateKey {
		t.Errorf("Export() with private key failed by value mismatch: %v", buf.String())
	}

	err = Export(LimitWriter(buf, 0), key)
	if err != ErrUnknownType {
		t.Errorf("Export() with private key failed: %v", err)
	}

	err = Export(LimitWriter(buf, 4), key)
	if err != ErrUnknownType {
		t.Errorf("Export() with private key failed: %v", err)
	}

	err = Export(LimitWriter(buf, 16), key)
	if err != ErrUnknownType {
		t.Errorf("Export() with private key failed: %v", err)
	}
}

// Unittest for Export with signature
func TestExport_Signature(t *testing.T) {
	sig, err := ImportSignature(strings.NewReader(testSignature))
	if err != nil {
		t.Errorf("ImportSignature() failed: %v", err)
	}

	buf := new(bytes.Buffer)
	err = Export(buf, sig)
	if err != nil {
		t.Errorf("Export() with signature failed: %v", err)
	}

	if buf.String() != testSignature {
		t.Errorf("Export() with signature failed by value mismatch: %v", buf.String())
	}

	err = Export(LimitWriter(buf, 0), sig)
	if err != ErrUnknownType {
		t.Errorf("Export() with signature failed: %v", err)
	}

	err = Export(LimitWriter(buf, 4), sig)
	if err != ErrUnknownType {
		t.Errorf("Export() with signature failed: %v", err)
	}

	err = Export(LimitWriter(buf, 16), sig)
	if err != ErrUnknownType {
		t.Errorf("Export() with signature failed: %v", err)
	}
}

func TestExport_Bad(t *testing.T) {
	sig, err := ImportSignature(strings.NewReader(testSignature))
	if err != nil {
		t.Errorf("ImportSignature() failed: %v", err)
	}

	buf := new(bytes.Buffer)
	err = Export(buf, nil)
	if err != ErrUnknownType {
		t.Errorf("Export() with signature failed: %v", err)
	}

	err = Export(nil, sig)
	if err != ErrNilWriter {
		t.Errorf("Export() with signature failed: %v", err)
	}
}
