package crypto

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestNewAesKey(t *testing.T) {
	key, err := NewAesKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(key) != 32 {
		t.Fatal("invalid aes key length, expected 32, got", len(key))
	}

	m := make(map[byte]struct{})
	for i := range key {
		m[key[i]] = struct{}{}
	}

	if len(m) <= 1 {
		t.Fatal("seems like generated AES key is not random")
	}
}

func TestKeySaving(t *testing.T) {
	priv, pub, err := NewRsaKeyPair(DefaultBits2048)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := BytesToRsaPrivateKey(RsaPrivateKeyToBytes(priv)); err != nil {
		t.Fatal(err)
	}

	b, err := RsaPublicKeyToBytes(pub)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := BytesToRsaPublicKey(b); err != nil {
		t.Fatal(err)
	}
}

func TestKmsRoundtrip(t *testing.T) {
	ctx := context.Background()

	key, err := NewAesKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := EncryptWithKms(
		ctx,
		key,
		os.Getenv("GOOGLE_PROJECT_ID"),
		os.Getenv("KMS_LOCATION"),
		os.Getenv("KMS_KEYRING"),
		os.Getenv("KMS_KEY"),
	)
	if err != nil {
		t.Fatal(err)
	}

	b, err = DecryptWithKms(
		ctx,
		b,
		os.Getenv("GOOGLE_PROJECT_ID"),
		os.Getenv("KMS_LOCATION"),
		os.Getenv("KMS_KEYRING"),
		os.Getenv("KMS_KEY"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b, key) {
		t.Fatal("data values do not match")
	}
}
