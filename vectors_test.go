package msign

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// vectors mirrors test-vectors/v1.json from the m-sign/specs repository.
type vectors struct {
	FormatVersion int `json:"format_version"`
	Keys          []struct {
		Name         string `json:"name"`
		SeedHex      string `json:"seed_hex"`
		PublicKeyHex string `json:"public_key_hex"`
		KeyIDHex     string `json:"key_id_hex"`
		Key          string `json:"key"`
		Pub          string `json:"pub"`
	} `json:"keys"`
	Signatures []struct {
		Name       string `json:"name"`
		Key        string `json:"key"`
		MessageHex string `json:"message_hex"`
		Sig        string `json:"sig"`
	} `json:"signatures"`
	Invalid []struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Input string `json:"input"`
		Error string `json:"error"`
	} `json:"invalid"`
	VerifyInvalid []struct {
		Name       string `json:"name"`
		Pub        string `json:"pub"`
		MessageHex string `json:"message_hex"`
		Sig        string `json:"sig"`
		Error      string `json:"error"`
	} `json:"verify_invalid"`
	AcceptedVariants []struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
	} `json:"accepted_variants"`
}

func loadVectors(t testing.TB) *vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors-v1.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decoding vectors: %v", err)
	}
	if v.FormatVersion != VersionOne {
		t.Fatalf("format_version = %d, want %d", v.FormatVersion, VersionOne)
	}
	return &v
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func exportString(t testing.TB, item Item) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Export(&buf, item); err != nil {
		t.Fatalf("Export() failed: %v", err)
	}
	return buf.String()
}

// importItem imports one item of the given vector type with both the
// Import and the Parse functions, and checks that they agree.
func importItem(t *testing.T, typ, input string) (Item, error) {
	t.Helper()
	var (
		fromReader, fromString Item
		errReader, errString   error
	)
	switch typ {
	case "key":
		fromReader, errReader = ImportPrivateKey(strings.NewReader(input))
		fromString, errString = ParsePrivateKey(input)
	case "pub":
		fromReader, errReader = ImportPublicKey(strings.NewReader(input))
		fromString, errString = ParsePublicKey(input)
	case "sig":
		fromReader, errReader = ImportSignature(strings.NewReader(input))
		fromString, errString = ParseSignature(input)
	default:
		t.Fatalf("unknown vector type %q", typ)
	}
	if (errReader == nil) != (errString == nil) {
		t.Fatalf("Import error %v, Parse error %v: they disagree", errReader, errString)
	}
	if errReader != nil {
		return nil, errReader
	}
	if a, b := exportString(t, fromReader), exportString(t, fromString); a != b {
		t.Fatalf("Import and Parse results differ: %q vs %q", a, b)
	}
	return fromReader, nil
}

func formatErrorFor(typ string) error {
	switch typ {
	case "key":
		return ErrInvalidKeyFormat
	case "pub":
		return ErrInvalidPubFormat
	default:
		return ErrInvalidSigFormat
	}
}

func TestVectorsKeys(t *testing.T) {
	v := loadVectors(t)
	for _, k := range v.Keys {
		t.Run(k.Name, func(t *testing.T) {
			priv, err := ParsePrivateKey(k.Key)
			if err != nil {
				t.Fatalf("ParsePrivateKey() failed: %v", err)
			}
			pub, err := ParsePublicKey(k.Pub)
			if err != nil {
				t.Fatalf("ParsePublicKey() failed: %v", err)
			}

			if got := priv.ID().String(); got != k.KeyIDHex {
				t.Errorf("private key ID = %s, want %s", got, k.KeyIDHex)
			}
			if got := pub.ID().String(); got != k.KeyIDHex {
				t.Errorf("public key ID = %s, want %s", got, k.KeyIDHex)
			}
			if got := exportString(t, priv); got != k.Key {
				t.Errorf("private key round trip = %q, want %q", got, k.Key)
			}
			if got := exportString(t, pub); got != k.Pub {
				t.Errorf("public key round trip = %q, want %q", got, k.Pub)
			}
			if got := exportString(t, priv.Public()); got != k.Pub {
				t.Errorf("Public() = %q, want %q", got, k.Pub)
			}

			p := priv.(*privateKeyV1)
			if got := hex.EncodeToString(p.bytes[:32]); got != k.SeedHex {
				t.Errorf("seed = %s, want %s", got, k.SeedHex)
			}
			if got := hex.EncodeToString(p.bytes[32:]); got != k.PublicKeyHex {
				t.Errorf("public half = %s, want %s", got, k.PublicKeyHex)
			}
		})
	}
}

func TestVectorsSignatures(t *testing.T) {
	v := loadVectors(t)
	keys := map[string]PrivateKey{}
	for _, k := range v.Keys {
		priv, err := ParsePrivateKey(k.Key)
		if err != nil {
			t.Fatalf("%s: ParsePrivateKey() failed: %v", k.Name, err)
		}
		keys[k.Name] = priv
	}

	for _, s := range v.Signatures {
		t.Run(s.Name, func(t *testing.T) {
			priv := keys[s.Key]
			msg := mustHex(t, s.MessageHex)

			// Ed25519 is deterministic, so signing must reproduce the vector.
			sig, err := priv.Sign(bytes.NewReader(msg))
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}
			if got := exportString(t, sig); got != s.Sig {
				t.Errorf("Sign() = %q, want %q", got, s.Sig)
			}

			imported, err := ImportSignature(strings.NewReader(s.Sig))
			if err != nil {
				t.Fatalf("ImportSignature() failed: %v", err)
			}
			if err := priv.Public().Verify(bytes.NewReader(msg), imported); err != nil {
				t.Errorf("Verify() failed: %v", err)
			}
		})
	}
}

func TestVectorsInvalid(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			_, err := importItem(t, c.Type, c.Input)
			if err == nil {
				t.Fatalf("invalid input %q accepted", c.Input)
			}
			if !errors.Is(err, formatErrorFor(c.Type)) {
				t.Errorf("error %v does not match %v", err, formatErrorFor(c.Type))
			}
			wantVersion := c.Error == "unsupported_version"
			if got := errors.Is(err, ErrUnsupportedVersion); got != wantVersion {
				t.Errorf("errors.Is(%v, ErrUnsupportedVersion) = %v, want %v", err, got, wantVersion)
			}
		})
	}
}

func TestVectorsVerifyInvalid(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.VerifyInvalid {
		t.Run(c.Name, func(t *testing.T) {
			pub, err := ParsePublicKey(c.Pub)
			if err != nil {
				t.Fatalf("ParsePublicKey() failed: %v", err)
			}
			sig, err := ParseSignature(c.Sig)
			if err != nil {
				t.Fatalf("ParseSignature() failed: %v", err)
			}

			err = pub.Verify(bytes.NewReader(mustHex(t, c.MessageHex)), sig)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("Verify() = %v, want an error matching ErrInvalidSignature", err)
			}
			wantMismatch := c.Error == "key_id_mismatch"
			if got := errors.Is(err, ErrKeyIDMismatch); got != wantMismatch {
				t.Errorf("errors.Is(%v, ErrKeyIDMismatch) = %v, want %v", err, got, wantMismatch)
			}
		})
	}
}

func TestVectorsAcceptedVariants(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.AcceptedVariants {
		t.Run(c.Name, func(t *testing.T) {
			item, err := importItem(t, c.Type, c.Input)
			if err != nil {
				t.Fatalf("variant rejected: %v", err)
			}
			if got := exportString(t, item); got != c.Canonical {
				t.Errorf("re-export = %q, want %q", got, c.Canonical)
			}
		})
	}
}
