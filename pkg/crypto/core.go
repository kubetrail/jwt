package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	kmsv1 "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	DefaultBits2048 = 2048
	publicKeyType   = "PUBLIC KEY"
	privateKeyType  = "PRIVATE KEY"
)

// NewAesKey generates new AES key
func NewAesKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		err := fmt.Errorf("could not create a rand AES key: %w", err)
		return nil, err
	}

	return key[:], nil
}

// NewRsaKeyPair generates a new RSA key pair
func NewRsaKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate RSA key pair: %w", err)
	}
	return privkey, &privkey.PublicKey, nil
}

// NewEcdsaKeyPair generates a new ECDSA key pair
func NewEcdsaKeyPair(pubkeyCurve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privatekey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate ECDSA key pair: %w", err)
	}

	return privatekey, &privatekey.PublicKey, nil
}

// NewEd25519KeyPair generates a new Ed25519 key pair
func NewEd25519KeyPair() (*ed25519.PrivateKey, *ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	return &privateKey, &publicKey, nil
}

// RsaPrivateKeyToBytes private key to bytes
func RsaPrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  privateKeyType,
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// EcdsaPrivateKeyToBytes private key to bytes
func EcdsaPrivateKeyToBytes(priv *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to x509 marshal ECDSA key: %w", err)
	}

	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  privateKeyType,
			Bytes: b,
		},
	)

	return privBytes, nil
}

// Ed25519PrivateKeyToBytes private key to bytes
func Ed25519PrivateKeyToBytes(priv *ed25519.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(*priv)
	if err != nil {
		return nil, fmt.Errorf("failed to x509 marshal Ed25519 key: %w", err)
	}

	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  privateKeyType,
			Bytes: b,
		},
	)

	return privBytes, nil
}

// RsaPublicKeyToBytes public key to bytes
func RsaPublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		err := fmt.Errorf("could not marshal public key: %w", err)
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  publicKeyType,
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// EcdsaPublicKeyToBytes public key to bytes
func EcdsaPublicKeyToBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		err := fmt.Errorf("could not marshal public key: %w", err)
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  publicKeyType,
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// Ed25519PublicKeyToBytes public key to bytes
func Ed25519PublicKeyToBytes(pub *ed25519.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(*pub)
	if err != nil {
		err := fmt.Errorf("could not marshal public key: %w", err)
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  publicKeyType,
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToRsaPrivateKey bytes to private key
func BytesToRsaPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse private key: %w", err)
		return nil, err
	}
	return key, nil
}

// BytesToEcdsaPrivateKey bytes to private key
func BytesToEcdsaPrivateKey(priv []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse private key: %w", err)
		return nil, err
	}
	return key, nil
}

// BytesToEd25519PrivateKey bytes to private key
func BytesToEd25519PrivateKey(priv []byte) (*ed25519.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	obj, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse private key: %w", err)
		return nil, err
	}

	key, ok := obj.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("type assertion error while parsing private key: %T", obj)
	}
	return key, nil
}

// BytesToRsaPublicKey bytes to public key
func BytesToRsaPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	d, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse public key: %w", err)
		return nil, err
	}
	key, ok := d.(*rsa.PublicKey)
	if !ok {
		err := fmt.Errorf("type assertion to public key failed")
		return nil, err
	}
	return key, nil
}

// BytesToEcdsaPublicKey bytes to public key
func BytesToEcdsaPublicKey(pub []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	d, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse public key: %w", err)
		return nil, err
	}
	key, ok := d.(*ecdsa.PublicKey)
	if !ok {
		err := fmt.Errorf("type assertion to public key failed")
		return nil, err
	}
	return key, nil
}

// BytesToEd25519PublicKey bytes to public key
func BytesToEd25519PublicKey(pub []byte) (*ed25519.PublicKey, error) {
	block, _ := pem.Decode(pub)
	d, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse public key: %w", err)
		return nil, err
	}
	key, ok := d.(*ed25519.PublicKey)
	if !ok {
		err := fmt.Errorf("type assertion to public key failed")
		return nil, err
	}
	return key, nil
}

// EncryptWithKms encrypts input data using Google KMS. You must have a service account
// referenced by env. var. GOOGLE_APPLICATION_CREDENTIALS
func EncryptWithKms(ctx context.Context,
	data []byte, project, location, keyring, key string) ([]byte, error) {
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		err := fmt.Errorf("failed to create kms client: %w", err)
		return nil, err
	}
	defer kmsClient.Close()

	resp, err := kmsClient.Encrypt(
		ctx,
		&kmsv1.EncryptRequest{
			Name: getKmsName(
				project,
				location,
				keyring,
				key,
			),
			Plaintext:                         data,
			AdditionalAuthenticatedData:       nil,
			PlaintextCrc32C:                   wrapperspb.Int64(int64(crc32Sum(data))),
			AdditionalAuthenticatedDataCrc32C: nil,
		},
	)
	if err != nil {
		err := fmt.Errorf("could not kms encrypt input: %w", err)
		return nil, err
	}

	return resp.Ciphertext, nil
}

// DecryptWithKms decrypts input data using Google KMS. You must have a service account
// referenced by env. var. GOOGLE_APPLICATION_CREDENTIALS
func DecryptWithKms(ctx context.Context,
	data []byte, project, location, keyring, key string) ([]byte, error) {
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		err := fmt.Errorf("failed to create kms client: %w", err)
		return nil, err
	}
	defer kmsClient.Close()

	resp, err := kmsClient.Decrypt(
		ctx,
		&kmsv1.DecryptRequest{
			Name: getKmsName(
				project,
				location,
				keyring,
				key,
			),
			Ciphertext:                        data,
			AdditionalAuthenticatedData:       nil,
			CiphertextCrc32C:                  wrapperspb.Int64(int64(crc32Sum(data))),
			AdditionalAuthenticatedDataCrc32C: nil,
		},
	)
	if err != nil {
		err := fmt.Errorf("could not kms decrypt input: %w", err)
		return nil, err
	}

	return resp.Plaintext, nil
}

// getKmsName constructs the canonical URI endpoint path for KMS encryption call
func getKmsName(projectId, kmsLocation, keyringName, keyName string) string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectId,
		kmsLocation,
		keyringName,
		keyName,
	)
}

// crc32Sum produces crc32 sum
func crc32Sum(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}
