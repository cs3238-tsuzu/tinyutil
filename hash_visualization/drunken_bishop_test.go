package tinyhv

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestDrunkenBishop(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("rsa.GenerateKey error:", err.Error())
	}
	pub := key.PublicKey

	s := struct {
		Name string
		E    *big.Int
		N    *big.Int
	}{
		ssh.KeyAlgoECDSA256,
		new(big.Int).SetInt64(int64(pub.E)),
		pub.N,
	}
	hash := sha256.Sum256(ssh.Marshal(s))

	str := DrunkenBiship("SHA512", hash[:], "RSA", 2048)

	if a := strings.Split(str, "\n"); len(a) != FLDSIZE_Y+2 {
		t.Fatalf("Incorrect height(must be %d): %d", FLDSIZE_Y+2, len(a))
	} else {
		for i := range a {
			if len(a[i]) != FLDSIZE_X+2 {
				t.Fatalf("Incorrect width(must be %d): %d", FLDSIZE_X+2, len(a[i]))
			}
		}
	}
}
