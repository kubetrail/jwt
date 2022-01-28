/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"path/filepath"

	"github.com/kubetrail/jwt/pkg/flags"
	"github.com/kubetrail/jwt/pkg/run"
	"github.com/spf13/cobra"
)

// encodeCmd represents the encode command
var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Encode key-value pairs in token",
	Long: `
Encode a set of key=value pairs in the token and
sign using private key.

Example:
jwt encode \
	--str=name=xyz \
	--str=loc=zz \
	--num=temp=25.7 \
	--num=pres=1000 \
	--bool=frozen=false \
	--bool=windy=true

In case the private key is not encrypted using Google KMS
please use --no-kms flag

Standard claims are inserted in the token, some of which
can be overridden:
jwt encode \
	--audience=self \
	--issuer=self \
	--active-in-seconds=10 \
	--expires-in-seconds=100

JWT token ID is set as a UUID internally. Furthermore,
the header will contain a UUID of the private key
which is generated using MD5 hash of the private key bytes.
`,
	RunE: run.Encode,
}

func init() {
	rootCmd.AddCommand(encodeCmd)
	f := encodeCmd.Flags()
	b := filepath.Base

	f.String(b(flags.KeyFile), "id", "Private key file (Env: PRIVATE_KEY)")
	f.String(b(flags.Alg), "RS256", "Signing algorithm")
	f.StringSlice(b(flags.Str), nil, "Encode string value (format: key=value)")
	f.StringSlice(b(flags.Num), nil, "Encode number value (format: key=value)")
	f.StringSlice(b(flags.Bool), nil, "Encode boolean value (format: key=value")
	f.String(b(flags.Issuer), "jwt-encode", "Token issuer")
	f.String(b(flags.Audience), "jwt-decode", "Token audience")
	f.String(b(flags.Subject), "", "Token subject")
	f.Int(b(flags.ActiveInSeconds), 0, "Token activation (0=always active)")
	f.Int(b(flags.ExpiresInSeconds), 0, "Token expiration (0=not expiring)")
}
