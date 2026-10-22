package msign_test

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/m-sign/msign"
)

func Example() {
	priv, pub, err := msign.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	sig, err := priv.Sign(strings.NewReader("release contents"))
	if err != nil {
		panic(err)
	}

	err = pub.Verify(strings.NewReader("release contents"), sig)
	fmt.Println("valid:", err == nil)

	err = pub.Verify(strings.NewReader("tampered contents"), sig)
	fmt.Println("tampered rejected:", errors.Is(err, msign.ErrInvalidSignature))
	// Output:
	// valid: true
	// tampered rejected: true
}

func ExampleParsePublicKey() {
	// A public key as it might be stored in an environment variable.
	pub, err := msign.ParsePublicKey("PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf")
	if err != nil {
		panic(err)
	}
	sig, err := msign.ParseSignature("SIG:AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk")
	if err != nil {
		panic(err)
	}

	fmt.Println("key id:", pub.ID())
	fmt.Println("valid:", pub.Verify(strings.NewReader(""), sig) == nil)
	// Output:
	// key id: 386e418a77ca
	// valid: true
}

func ExampleExport() {
	pub, err := msign.ParsePublicKey("PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf")
	if err != nil {
		panic(err)
	}
	if err := msign.Export(os.Stdout, pub); err != nil {
		panic(err)
	}
	// Output:
	// PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf
}

func ExamplePrivateKey_formatting() {
	priv, err := msign.ParsePrivateKey("KEY:Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8")
	if err != nil {
		panic(err)
	}
	// Printing a private key never reveals key material.
	fmt.Println(priv)
	// Output:
	// msign.PrivateKey(386e418a77ca)
}
