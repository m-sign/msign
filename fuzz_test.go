package msign

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// addVectorSeeds adds every vector input of the given type to the corpus.
func addVectorSeeds(f *testing.F, typ string) {
	v := loadVectors(f)
	for _, k := range v.Keys {
		switch typ {
		case "key":
			f.Add(k.Key)
		case "pub":
			f.Add(k.Pub)
		}
	}
	if typ == "sig" {
		for _, s := range v.Signatures {
			f.Add(s.Sig)
		}
	}
	for _, c := range v.Invalid {
		if c.Type == typ {
			f.Add(c.Input)
		}
	}
	for _, c := range v.AcceptedVariants {
		if c.Type == typ {
			f.Add(c.Input)
		}
	}
}

// checkCanonical checks that an accepted input re-encodes to itself, minus
// its optional terminator: there is exactly one valid text for every item.
func checkCanonical(t *testing.T, input string, item Item) {
	t.Helper()
	line := strings.TrimSuffix(input, "\n")
	line = strings.TrimSuffix(line, "\r")
	if got := string(item.appendText(nil)); got != line {
		t.Fatalf("accepted %q but it re-encodes to %q", input, got)
	}
}

func FuzzParsePublicKey(f *testing.F) {
	addVectorSeeds(f, "pub")
	f.Fuzz(func(t *testing.T, s string) {
		pub, err := ParsePublicKey(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidPubFormat) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		checkCanonical(t, s, pub)
	})
}

func FuzzParsePrivateKey(f *testing.F) {
	addVectorSeeds(f, "key")
	f.Fuzz(func(t *testing.T, s string) {
		priv, err := ParsePrivateKey(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidKeyFormat) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		checkCanonical(t, s, priv)
	})
}

func FuzzParseSignature(f *testing.F) {
	addVectorSeeds(f, "sig")
	f.Fuzz(func(t *testing.T, s string) {
		sig, err := ParseSignature(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidSigFormat) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		checkCanonical(t, s, sig)
	})
}

// FuzzImport feeds arbitrary bytes to every Import function. They must not
// panic, and anything they accept must be the first line of the input.
func FuzzImport(f *testing.F) {
	f.Add([]byte(testPublicKey + testSignature))
	f.Add([]byte(testPrivateKey))
	f.Add([]byte("PUB:\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		first, _, _ := strings.Cut(string(data), "\n")
		if pub, err := ImportPublicKey(bytes.NewReader(data)); err == nil {
			checkCanonical(t, first, pub)
		}
		if priv, err := ImportPrivateKey(bytes.NewReader(data)); err == nil {
			checkCanonical(t, first, priv)
		}
		if sig, err := ImportSignature(bytes.NewReader(data)); err == nil {
			checkCanonical(t, first, sig)
		}
	})
}

func FuzzSignVerify(f *testing.F) {
	f.Add([]byte(""), uint16(0))
	f.Add([]byte("abc"), uint16(1))
	priv := mustParseKey(f)
	pub := priv.Public()
	f.Fuzz(func(t *testing.T, msg []byte, flip uint16) {
		sig, err := priv.Sign(bytes.NewReader(msg))
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		if err := pub.Verify(bytes.NewReader(msg), sig); err != nil {
			t.Fatalf("Verify() of a fresh signature failed: %v", err)
		}
		if len(msg) == 0 {
			return
		}
		changed := bytes.Clone(msg)
		changed[int(flip)%len(changed)] ^= 0x01
		if err := pub.Verify(bytes.NewReader(changed), sig); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("Verify() of a changed message = %v, want ErrInvalidSignature", err)
		}
	})
}
