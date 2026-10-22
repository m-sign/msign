package msign

import (
	"bytes"
	"errors"
	"testing"
)

func TestGetV1PayloadLengths(t *testing.T) {
	tests := []struct {
		name  string
		parse func([]byte) error
		size  int
		want  error
	}{
		{"public key", func(b []byte) error { _, err := getPublicKeyV1(b); return err }, sizePubV1, ErrInvalidPubFormat},
		{"private key", func(b []byte) error { _, err := getPrivateKeyV1(b); return err }, sizeKeyV1, ErrInvalidKeyFormat},
		{"signature", func(b []byte) error { _, err := getSignatureV1(b); return err }, sizeSigV1, ErrInvalidSigFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, n := range []int{0, 1, tt.size - 1, tt.size + 1} {
				payload := make([]byte, n)
				if n > 0 {
					payload[0] = VersionOne
				}
				if err := tt.parse(payload); !errors.Is(err, tt.want) {
					t.Errorf("%d-byte payload: error = %v, want %v", n, err, tt.want)
				}
			}
		})
	}
}

func TestV1Sizes(t *testing.T) {
	if sizeKeyV1 != 77 || sizePubV1 != 39 || sizeSigV1 != 77 {
		t.Errorf("payload sizes = %d/%d/%d, want 77/39/77", sizeKeyV1, sizePubV1, sizeSigV1)
	}
}

func BenchmarkSign(b *testing.B) {
	priv := mustParseKey(b)
	for _, size := range []int{1 << 10, 1 << 20} {
		msg := bytes.Repeat([]byte{'a'}, size)
		b.Run(byteSize(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := priv.Sign(bytes.NewReader(msg)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	priv := mustParseKey(b)
	pub := priv.Public()
	for _, size := range []int{1 << 10, 1 << 20} {
		msg := bytes.Repeat([]byte{'a'}, size)
		sig, err := priv.Sign(bytes.NewReader(msg))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(byteSize(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				if err := pub.Verify(bytes.NewReader(msg), sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkImport(b *testing.B) {
	b.Run("private key", func(b *testing.B) {
		for b.Loop() {
			if _, err := ParsePrivateKey(testPrivateKey); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("public key", func(b *testing.B) {
		for b.Loop() {
			if _, err := ParsePublicKey(testPublicKey); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("signature", func(b *testing.B) {
		for b.Loop() {
			if _, err := ParseSignature(testSignature); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func byteSize(n int) string {
	if n >= 1<<20 {
		return "1MiB"
	}
	return "1KiB"
}
