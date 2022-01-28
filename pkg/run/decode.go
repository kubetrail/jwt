package run

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/kubetrail/jwt/pkg/crypto"
	"github.com/kubetrail/jwt/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Token struct {
	Header map[string]interface{} `json:"header,omitempty"`
	Claims jwt.Claims             `json:"claims,omitempty"`
	Valid  bool                   `json:"valid"`
}

func Decode(cmd *cobra.Command, args []string) error {
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.KeyFile, cmd.Flags().Lookup(filepath.Base(flags.KeyFile)))
	_ = viper.BindPFlag(flags.SkipValidation, cmd.Flags().Lookup(filepath.Base(flags.SkipValidation)))
	_ = viper.BindEnv(flags.KeyFile, "PUBLIC_KEY")

	keyFile := viper.GetString(flags.KeyFile)
	skipValidation := viper.GetBool(flags.SkipValidation)
	var tokenString string
	var alg string

	// read JWT token either from argument or STDIN
	if len(args) > 0 {
		if len(args) > 1 {
			return fmt.Errorf("only one argument is allowed")
		}
		tokenString = args[0]
	} else {
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read from STDIN: %w", err)
		}
		tokenString = string(b)
	}

	token, err := jwt.Parse(tokenString, nil)
	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return fmt.Errorf("malformed token: %w", err)
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return fmt.Errorf("either expired or not yet active token: %w", err)
		} else {
			if !skipValidation {
				alg, ok = token.Header["alg"].(string)
				if !ok {
					return fmt.Errorf("failed to get token signing algorithm")
				}
			}
		}
	}

	if err := setAppCredsEnvVar(persistentFlags.ApplicationCredentials); err != nil {
		err := fmt.Errorf("could not set Google Application credentials env. var: %w", err)
		return err
	}

	if keyFile == "-" {
		return fmt.Errorf("key input via STDIN is not allowed")
	}

	var publicBytes []byte
	var keyFunc jwt.Keyfunc

	if !skipValidation {
		publicBytes, err = os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("could not read keyfile: %w", err)
		}
	}

	if !skipValidation {
		switch strings.ToUpper(alg) {
		case HS256, HS384, HS512:
			keyFunc = func(token *jwt.Token) (interface{}, error) {
				return publicBytes, nil
			}
		case RS256, RS384, RS512:
			publicKey, err := crypto.BytesToRsaPublicKey(publicBytes)
			if err != nil {
				return fmt.Errorf("failed to load private key: %w", err)
			}
			keyFunc = func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			}
		case ES256, ES384, ES512:
			publicKey, err := crypto.BytesToEcdsaPublicKey(publicBytes)
			if err != nil {
				return fmt.Errorf("failed to load private key: %w", err)
			}
			keyFunc = func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			}
		case strings.ToUpper(Ed25519):
			publicKey, err := crypto.BytesToEd25519PublicKey(publicBytes)
			if err != nil {
				return fmt.Errorf("failed to load private key: %w", err)
			}
			keyFunc = func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			}
		default:
			return fmt.Errorf("invalid keygen algorithm: %s", alg)
		}
	}

	token, err = jwt.Parse(tokenString, keyFunc)
	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return fmt.Errorf("malformed token: %w", err)
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return fmt.Errorf("either expired or not yet active token: %w", err)
		} else {
			if !skipValidation {
				return fmt.Errorf("failed to parse token: %w", err)
			}
		}
	}

	b, err := json.Marshal(
		&Token{
			Header: token.Header,
			Claims: token.Claims,
			Valid:  token.Valid,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to serialize output: %w", err)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(b)); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	return nil
}
