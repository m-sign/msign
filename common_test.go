package msign

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// Test key kat-a from the specification's test vectors. It is a published
// test key: never use it for real signing.
const (
	testPrivateKey = "KEY:Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8\n"
	testPublicKey  = "PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf\n"
	testKeyID      = "386e418a77ca"
	testSeedHex    = "3f1f6bd5178138c2aec10f06623e7dd99dcc9a85386ebabb626defed96f6ff02"
	// testSignature is the kat-a signature of the empty message.
	testSignature = "SIG:AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk\n"
)

var errLimit = errors.New("write limit reached")

// limitedWriter fails with errLimit once n bytes have been written.
type limitedWriter struct {
	w io.Writer
	n int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n < len(p) {
		n, _ := lw.w.Write(p[:lw.n])
		lw.n = 0
		return n, errLimit
	}
	lw.n -= len(p)
	return lw.w.Write(p)
}

// onlyReader hides every method of a reader except Read.
type onlyReader struct {
	io.Reader
}

func mustParseKey(t testing.TB) PrivateKey {
	t.Helper()
	priv, err := ParsePrivateKey(testPrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey() failed: %v", err)
	}
	return priv
}

func TestNewPrivateKey(t *testing.T) {
	priv, pub, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() failed: %v", err)
	}
	if !bytes.Equal(priv.ID(), pub.ID()) {
		t.Errorf("IDs differ: %s vs %s", priv.ID(), pub.ID())
	}
	if exportString(t, priv.Public()) != exportString(t, pub) {
		t.Error("Public() differs from the generated public key")
	}

	// The generated key must survive a round trip through its text form.
	again, err := ParsePrivateKey(exportString(t, priv))
	if err != nil {
		t.Fatalf("ParsePrivateKey(generated) failed: %v", err)
	}
	if exportString(t, again) != exportString(t, priv) {
		t.Error("generated private key does not round-trip")
	}
}

func TestSignVerify(t *testing.T) {
	priv, pub, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() failed: %v", err)
	}
	msg := []byte("Hello World!")

	sig, err := priv.Sign(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if !bytes.Equal(sig.KeyID(), pub.ID()) {
		t.Errorf("signature KeyID = %s, want %s", sig.KeyID(), pub.ID())
	}
	if err := pub.Verify(bytes.NewReader(msg), sig); err != nil {
		t.Errorf("Verify() failed: %v", err)
	}

	tampered := bytes.Clone(msg)
	tampered[0] = 'h'
	err = pub.Verify(bytes.NewReader(tampered), sig)
	if !errors.Is(err, ErrInvalidSignature) || errors.Is(err, ErrKeyIDMismatch) {
		t.Errorf("Verify(tampered) = %v, want ErrInvalidSignature", err)
	}

	otherPub := mustParseKey(t).Public()
	if err := otherPub.Verify(bytes.NewReader(msg), sig); !errors.Is(err, ErrKeyIDMismatch) || !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify(other key) = %v, want ErrKeyIDMismatch matching ErrInvalidSignature", err)
	}
}

func TestSignVerifyErrors(t *testing.T) {
	priv := mustParseKey(t)
	pub := priv.Public()
	sig, err := ParseSignature(testSignature)
	if err != nil {
		t.Fatalf("ParseSignature() failed: %v", err)
	}
	errRead := errors.New("read failed")

	tests := []struct {
		name string
		err  error
		want error
	}{
		{"sign nil reader", func() error { _, err := priv.Sign(nil); return err }(), ErrNilReader},
		{"sign read error", func() error { _, err := priv.Sign(iotest.ErrReader(errRead)); return err }(), errRead},
		{"verify nil reader", pub.Verify(nil, sig), ErrNilReader},
		{"verify read error", pub.Verify(iotest.ErrReader(errRead), sig), errRead},
		{"verify nil signature", pub.Verify(strings.NewReader(""), nil), ErrInvalidSignature},
		{"verify ok", pub.Verify(strings.NewReader(""), sig), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.want) || (tt.want == nil && tt.err != nil) {
				t.Errorf("error = %v, want %v", tt.err, tt.want)
			}
		})
	}

	// A read error is not a verification failure.
	if err := pub.Verify(iotest.ErrReader(errRead), sig); errors.Is(err, ErrInvalidSignature) {
		t.Errorf("read error %v must not match ErrInvalidSignature", err)
	}
}

func TestKeyID(t *testing.T) {
	priv := mustParseKey(t)
	if got := priv.ID().String(); got != testKeyID {
		t.Errorf("ID() = %s, want %s", got, testKeyID)
	}

	// ID returns a copy: changing it must not change the key.
	id := priv.ID()
	id[0] ^= 0xff
	if got := priv.ID().String(); got != testKeyID {
		t.Errorf("ID() changed to %s after modifying a returned copy", got)
	}

	sig, err := ParseSignature(testSignature)
	if err != nil {
		t.Fatalf("ParseSignature() failed: %v", err)
	}
	if got := sig.KeyID().String(); got != testKeyID {
		t.Errorf("signature KeyID() = %s, want %s", got, testKeyID)
	}
}

func TestStringMethods(t *testing.T) {
	pub, err := ParsePublicKey(testPublicKey)
	if err != nil {
		t.Fatalf("ParsePublicKey() failed: %v", err)
	}
	if got, want := pub.String(), strings.TrimSuffix(testPublicKey, "\n"); got != want {
		t.Errorf("PublicKey.String() = %q, want %q", got, want)
	}

	sig, err := ParseSignature(testSignature)
	if err != nil {
		t.Fatalf("ParseSignature() failed: %v", err)
	}
	if got, want := sig.String(), strings.TrimSuffix(testSignature, "\n"); got != want {
		t.Errorf("Signature.String() = %q, want %q", got, want)
	}
}

func TestPrivateKeyRedaction(t *testing.T) {
	priv := mustParseKey(t)
	secret := []string{
		testSeedHex,
		strings.ToUpper(testSeedHex),
		strings.TrimSuffix(strings.TrimPrefix(testPrivateKey, PrefixKEY), "\n"),
	}
	want := "msign.PrivateKey(" + testKeyID + ")"

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		got := fmt.Sprintf(verb, priv)
		for _, s := range secret {
			if strings.Contains(got, s) {
				t.Errorf("Sprintf(%q) leaks key material: %q", verb, got)
			}
		}
		if verb != "%T" && got != want {
			t.Errorf("Sprintf(%q) = %q, want %q", verb, got, want)
		}
	}
}

func TestImportReadsOneLine(t *testing.T) {
	stream := testPublicKey + testSignature + "rest"
	readers := map[string]func() io.Reader{
		"strings.Reader": func() io.Reader { return strings.NewReader(stream) },
		"plain reader":   func() io.Reader { return onlyReader{strings.NewReader(stream)} },
		"one byte reads": func() io.Reader { return iotest.OneByteReader(strings.NewReader(stream)) },
	}
	for name, newReader := range readers {
		t.Run(name, func(t *testing.T) {
			r := newReader()
			if _, err := ImportPublicKey(r); err != nil {
				t.Fatalf("ImportPublicKey() failed: %v", err)
			}
			if _, err := ImportSignature(r); err != nil {
				t.Fatalf("ImportSignature() after a public key failed: %v", err)
			}
			rest, err := io.ReadAll(r)
			if err != nil || string(rest) != "rest" {
				t.Errorf("remaining input = %q, %v; want %q", rest, err, "rest")
			}
		})
	}
}

func TestImportErrors(t *testing.T) {
	errRead := errors.New("read failed")
	long := PrefixPUB + strings.Repeat("A", 10<<20)

	tests := []struct {
		name string
		r    io.Reader
		want error
	}{
		{"nil reader", nil, ErrNilReader},
		{"empty input", strings.NewReader(""), ErrInvalidPubFormat},
		{"immediate EOF error", iotest.ErrReader(io.EOF), ErrInvalidPubFormat},
		{"read error", iotest.ErrReader(errRead), errRead},
		{"read error mid-line", io.MultiReader(strings.NewReader("PUB:AAA"), iotest.ErrReader(errRead)), errRead},
		{"line too long", strings.NewReader(long), ErrInvalidPubFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ImportPublicKey(tt.r)
			if !errors.Is(err, tt.want) {
				t.Errorf("ImportPublicKey() error = %v, want %v", err, tt.want)
			}
		})
	}

	// The other import functions share the reader; check their nil handling.
	if _, err := ImportPrivateKey(nil); !errors.Is(err, ErrNilReader) {
		t.Errorf("ImportPrivateKey(nil) = %v, want ErrNilReader", err)
	}
	if _, err := ImportSignature(nil); !errors.Is(err, ErrNilReader) {
		t.Errorf("ImportSignature(nil) = %v, want ErrNilReader", err)
	}
}

func TestParseErrors(t *testing.T) {
	pubLine := strings.TrimSuffix(testPublicKey, "\n")
	tests := []struct {
		name  string
		parse func(string) error
		input string
		want  error
	}{
		{"pub two lines", func(s string) error { _, err := ParsePublicKey(s); return err }, pubLine + "\n" + pubLine, ErrInvalidPubFormat},
		{"key two lines", func(s string) error { _, err := ParsePrivateKey(s); return err }, "KEY:\nKEY:", ErrInvalidKeyFormat},
		{"sig two lines", func(s string) error { _, err := ParseSignature(s); return err }, "SIG:\nSIG:", ErrInvalidSigFormat},
		{"pub trailing CR without LF", func(s string) error { _, err := ParsePublicKey(s); return err }, pubLine + "\r", ErrInvalidPubFormat},
		{"single base64 char", func(s string) error { _, err := ParsePublicKey(s); return err }, "PUB:A", ErrInvalidPubFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.parse(tt.input); !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestExport(t *testing.T) {
	priv := mustParseKey(t)
	sig, err := ParseSignature(testSignature)
	if err != nil {
		t.Fatalf("ParseSignature() failed: %v", err)
	}

	items := []struct {
		name string
		item Item
		want string
	}{
		{"private key", priv, testPrivateKey},
		{"public key", priv.Public(), testPublicKey},
		{"signature", sig, testSignature},
	}
	for _, tt := range items {
		t.Run(tt.name, func(t *testing.T) {
			if got := exportString(t, tt.item); got != tt.want {
				t.Errorf("Export() = %q, want %q", got, tt.want)
			}
			for _, limit := range []int{0, 4, len(tt.want) - 1} {
				var buf bytes.Buffer
				err := Export(&limitedWriter{w: &buf, n: limit}, tt.item)
				if !errors.Is(err, errLimit) {
					t.Errorf("Export() with limit %d = %v, want errLimit", limit, err)
				}
			}
		})
	}

	if err := Export(new(bytes.Buffer), nil); !errors.Is(err, ErrUnknownType) {
		t.Errorf("Export(nil item) = %v, want ErrUnknownType", err)
	}
	if err := Export(nil, sig); !errors.Is(err, ErrNilWriter) {
		t.Errorf("Export(nil writer) = %v, want ErrNilWriter", err)
	}
}
