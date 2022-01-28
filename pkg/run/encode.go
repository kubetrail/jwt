package run

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/kubetrail/jwt/pkg/crypto"
	"github.com/kubetrail/jwt/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Encode(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	persistentFlags := getPersistentFlags(cmd)

	_ = viper.BindPFlag(flags.KeyFile, cmd.Flags().Lookup(filepath.Base(flags.KeyFile)))
	_ = viper.BindEnv(flags.KeyFile, "PRIVATE_KEY")
	_ = viper.BindPFlag(flags.Alg, cmd.Flags().Lookup(filepath.Base(flags.Alg)))
	_ = viper.BindEnv(flags.Alg, "KEYGEN_ALGORITHM")

	_ = viper.BindPFlag(flags.Str, cmd.Flags().Lookup(filepath.Base(flags.Str)))
	_ = viper.BindPFlag(flags.Num, cmd.Flags().Lookup(filepath.Base(flags.Num)))
	_ = viper.BindPFlag(flags.Bool, cmd.Flags().Lookup(filepath.Base(flags.Bool)))

	_ = viper.BindPFlag(flags.Issuer, cmd.Flags().Lookup(filepath.Base(flags.Issuer)))
	_ = viper.BindPFlag(flags.Audience, cmd.Flags().Lookup(filepath.Base(flags.Audience)))
	_ = viper.BindPFlag(flags.Subject, cmd.Flags().Lookup(filepath.Base(flags.Subject)))
	_ = viper.BindPFlag(flags.ActiveInSeconds, cmd.Flags().Lookup(filepath.Base(flags.ActiveInSeconds)))
	_ = viper.BindPFlag(flags.ExpiresInSeconds, cmd.Flags().Lookup(filepath.Base(flags.ExpiresInSeconds)))

	keyFile := viper.GetString(flags.KeyFile)
	alg := viper.GetString(flags.Alg)
	strPairs := viper.GetStringSlice(flags.Str)
	numPairs := viper.GetStringSlice(flags.Num)
	boolPairs := viper.GetStringSlice(flags.Bool)

	issuer := viper.GetString(flags.Issuer)
	audience := viper.GetString(flags.Audience)
	subject := viper.GetString(flags.Subject)
	active := viper.GetInt(flags.ActiveInSeconds)
	expiresInSeconds := viper.GetInt(flags.ExpiresInSeconds)

	if err := setAppCredsEnvVar(persistentFlags.ApplicationCredentials); err != nil {
		err := fmt.Errorf("could not set Google Application credentials env. var: %w", err)
		return err
	}

	if keyFile == "-" {
		return fmt.Errorf("key input via STDIN is not allowed")
	}

	var privateBytes []byte
	var err error
	var signingKey interface{}
	var signingMethod jwt.SigningMethod
	var claims jwt.MapClaims
	var tokenString string

	privateBytes, err = os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("could not read keyfile: %w", err)
	}

	if !persistentFlags.NoKms {
		privateBytes, err = crypto.DecryptWithKms(
			ctx,
			privateBytes,
			persistentFlags.Project,
			persistentFlags.Location,
			persistentFlags.Keyring,
			persistentFlags.Key,
		)
		if err != nil {
			return fmt.Errorf("could not decrypt key using KMS: %w", err)
		}
	}

	switch strings.ToUpper(alg) {
	case HS256, HS384, HS512:
		signingKey = privateBytes
	case RS256, RS384, RS512:
		privateKey, err := crypto.BytesToRsaPrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
		signingKey = privateKey
	case ES256, ES384, ES512:
		privateKey, err := crypto.BytesToEcdsaPrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
		signingKey = privateKey
	case strings.ToUpper(Ed25519):
		privateKey, err := crypto.BytesToEd25519PrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
		signingKey = privateKey
	default:
		return fmt.Errorf("invalid keygen algorithm: %s", alg)
	}

	switch strings.ToUpper(alg) {
	case HS256:
		signingMethod = jwt.SigningMethodHS256
	case HS384:
		signingMethod = jwt.SigningMethodHS384
	case HS512:
		signingMethod = jwt.SigningMethodHS512
	case RS256:
		signingMethod = jwt.SigningMethodRS256
	case RS384:
		signingMethod = jwt.SigningMethodRS384
	case RS512:
		signingMethod = jwt.SigningMethodRS512
	case ES256:
		signingMethod = jwt.SigningMethodES256
	case ES384:
		signingMethod = jwt.SigningMethodES384
	case ES512:
		signingMethod = jwt.SigningMethodES512
	case strings.ToUpper(Ed25519):
		signingMethod = jwt.SigningMethodEdDSA
	default:
		return fmt.Errorf("invalid keygen algorithm: %s", alg)
	}

	var expiresAt int64
	var notBefore int64
	var issuedAt int64
	if active > 0 {
		notBefore = time.Now().Add(time.Second * time.Duration(active)).Unix()
	}
	issuedAt = time.Now().Unix()
	if expiresInSeconds > 0 {
		expiresAt = time.Now().Add(time.Second * time.Duration(expiresInSeconds)).Unix()
	}
	claims = make(map[string]interface{})
	stdClaims := jwt.StandardClaims{
		Audience:  audience,
		ExpiresAt: expiresAt,
		Id:        uuid.New().String(),
		IssuedAt:  issuedAt,
		Issuer:    issuer,
		NotBefore: notBefore,
		Subject:   subject,
	}
	if jb, err := json.Marshal(stdClaims); err != nil {
		return fmt.Errorf("failed to serialize std claims: %w", err)
	} else {
		if err := json.Unmarshal(jb, &claims); err != nil {
			return fmt.Errorf("failed to deserialize std claims: %w", err)
		}
	}

	for _, arg := range args {
		parts := strings.Split(arg, "=")
		if len(parts) < 2 {
			return fmt.Errorf("invalid arg %s not in key=value format", arg)
		}
		if _, ok := claims[parts[0]]; ok {
			return fmt.Errorf("duplicate key %s", parts[0])
		}
		claims[parts[0]] = strings.Join(parts[1:], "=")
	}

	for _, arg := range strPairs {
		parts := strings.Split(arg, "=")
		if len(parts) < 2 {
			return fmt.Errorf("invalid arg %s not in key=value format", arg)
		}
		if _, ok := claims[parts[0]]; ok {
			return fmt.Errorf("duplicate key %s", parts[0])
		}
		claims[parts[0]] = strings.Join(parts[1:], "=")
	}

	for _, arg := range numPairs {
		parts := strings.Split(arg, "=")
		if len(parts) != 2 {
			return fmt.Errorf("invalid arg %s not in key=value format with numeral value", arg)
		}
		if _, ok := claims[parts[0]]; ok {
			return fmt.Errorf("duplicate key %s", parts[0])
		}

		if v, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			claims[parts[0]] = v
			continue
		}

		if v, err := strconv.ParseFloat(parts[1], 64); err == nil {
			claims[parts[0]] = v
			continue
		}

		return fmt.Errorf("failed to parse value in arg as numeral: %s", arg)
	}

	for _, arg := range boolPairs {
		parts := strings.Split(arg, "=")
		if len(parts) != 2 {
			return fmt.Errorf("invalid arg %s not in key=value format with boolean value", arg)
		}
		if _, ok := claims[parts[0]]; ok {
			return fmt.Errorf("duplicate key %s", parts[0])
		}

		if strings.ToLower(parts[1]) == "true" {
			claims[parts[0]] = true
			continue
		}

		if strings.ToLower(parts[1]) == "false" {
			claims[parts[0]] = false
			continue
		}

		return fmt.Errorf("failed to parse value in arg as boolean: %s", arg)
	}

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	md5sum := md5.Sum(privateBytes)
	uid, err := uuid.FromBytes(md5sum[:])
	if err != nil {
		return fmt.Errorf("failed to generate uuid: %w", err)
	}
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = uid.String()

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err = token.SignedString(signingKey)
	if err != nil {
		return fmt.Errorf("failed to sign token: %w", err)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), tokenString); err != nil {
		return fmt.Errorf("failed to write token to output: %w", err)
	}

	return nil
}
