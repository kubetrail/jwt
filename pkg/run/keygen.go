package run

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubetrail/jwt/pkg/crypto"
	"github.com/kubetrail/jwt/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Keygen(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.KeyFile, cmd.Flags().Lookup(filepath.Base(flags.KeyFile)))
	_ = viper.BindPFlag(flags.Alg, cmd.Flags().Lookup(filepath.Base(flags.Alg)))
	_ = viper.BindEnv(flags.Alg, "KEYGEN_ALGORITHM")

	keyFile := viper.GetString(flags.KeyFile)
	alg := viper.GetString(flags.Alg)

	if err := setAppCredsEnvVar(persistentFlags.ApplicationCredentials); err != nil {
		err := fmt.Errorf("could not set Google Application credentials env. var: %w", err)
		return err
	}

	var privBytes []byte
	var pubBytes []byte
	var err error

	switch strings.ToUpper(alg) {
	case HS256, HS384, HS512:
		privBytes, err = crypto.NewAesKey()
		if err != nil {
			return fmt.Errorf("failed to generate HMAC key: %w", err)
		}
	case RS256, RS384, RS512:
		priv, pub, err := crypto.NewRsaKeyPair(crypto.DefaultBits2048)
		if err != nil {
			return fmt.Errorf("could not generate RSA keypairs: %w", err)
		}

		privBytes = crypto.RsaPrivateKeyToBytes(priv)
		pubBytes, err = crypto.RsaPublicKeyToBytes(pub)
		if err != nil {
			return fmt.Errorf("could not generate PEM for public key: %w", err)
		}

	case ES256:
		priv, pub, err := crypto.NewEcdsaKeyPair(elliptic.P256())
		if err != nil {
			return fmt.Errorf("failed to generate new ECDSA key pair: %w", err)
		}
		privBytes, err = crypto.EcdsaPrivateKeyToBytes(priv)
		if err != nil {
			return fmt.Errorf("could not generate PEM for private key: %w", err)
		}
		pubBytes, err = crypto.EcdsaPublicKeyToBytes(pub)
		if err != nil {
			return fmt.Errorf("could not generate PEM for public key: %w", err)
		}
	case ES384:
		priv, pub, err := crypto.NewEcdsaKeyPair(elliptic.P384())
		if err != nil {
			return fmt.Errorf("failed to generate new ECDSA key pair: %w", err)
		}
		privBytes, err = crypto.EcdsaPrivateKeyToBytes(priv)
		if err != nil {
			return fmt.Errorf("could not generate PEM for private key: %w", err)
		}
		pubBytes, err = crypto.EcdsaPublicKeyToBytes(pub)
		if err != nil {
			return fmt.Errorf("could not generate PEM for public key: %w", err)
		}
	case ES512:
		priv, pub, err := crypto.NewEcdsaKeyPair(elliptic.P521())
		if err != nil {
			return fmt.Errorf("failed to generate new ECDSA key pair: %w", err)
		}
		privBytes, err = crypto.EcdsaPrivateKeyToBytes(priv)
		if err != nil {
			return fmt.Errorf("could not generate PEM for private key: %w", err)
		}
		pubBytes, err = crypto.EcdsaPublicKeyToBytes(pub)
		if err != nil {
			return fmt.Errorf("could not generate PEM for public key: %w", err)
		}
	case strings.ToUpper(Ed25519):
		priv, pub, err := crypto.NewEd25519KeyPair()
		if err != nil {
			return fmt.Errorf("failed to new ED25519 key pair: %w", err)
		}
		privBytes, err = crypto.Ed25519PrivateKeyToBytes(priv)
		if err != nil {
			return fmt.Errorf("failed to get PEM encoding for private key: %w", err)
		}
		pubBytes, err = crypto.Ed25519PublicKeyToBytes(pub)
		if err != nil {
			return fmt.Errorf("failed to get PEM encoding for public key: %w", err)
		}
	default:
		return fmt.Errorf("invalid keygen algorithm: %s", alg)
	}

	if !persistentFlags.NoKms {
		privBytes, err = crypto.EncryptWithKms(
			ctx,
			privBytes,
			persistentFlags.Project,
			persistentFlags.Location,
			persistentFlags.Keyring,
			persistentFlags.Key,
		)
		if err != nil {
			return fmt.Errorf("could not encrypt private key via KMS: %w", err)
		}
	}

	if keyFile == "-" {
		if persistentFlags.NoKms {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(privBytes))
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(pubBytes))
		} else {
			jb, err := json.Marshal(
				struct {
					PrivateKey []byte `json:"privateKey,omitempty"`
					PublicKey  []byte `json:"publicKey,omitempty"`
				}{
					PrivateKey: privBytes,
					PublicKey:  pubBytes,
				},
			)
			if err != nil {
				return fmt.Errorf("could not serialize output for keys: %w", err)
			}

			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(jb))
		}

		return nil
	}

	if err := os.WriteFile(keyFile, privBytes, 0600); err != nil {
		return fmt.Errorf("could not write private key to file: %w", err)
	}

	if len(pubBytes) > 0 {
		if err := os.WriteFile(fmt.Sprintf("%s.pub", keyFile), pubBytes, 0600); err != nil {
			return fmt.Errorf("could not write public key to file: %w", err)
		}
	}

	return nil
}
