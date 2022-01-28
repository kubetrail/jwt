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

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decode JWT token",
	Long: `
Decode JWT token to JSON

Example:
jwt encode \
	--str=name=xyz \
	--str=loc=zz \
	--num=temp=25.7 \
	--num=pres=1000 \
	--bool=frozen=false \
	--bool=windy=true \
	| jwt decode \
	| jq '.'
{
  "header": {
    "alg": "RS256",
    "kid": "f5949688-3787-0140-a4bf-bee3fe7d36d3",
    "typ": "JWT"
  },
  "claims": {
    "aud": "jwt-decode",
    "frozen": false,
    "iat": 1643379005,
    "iss": "jwt-encode",
    "jti": "7e0b960c-fcb8-4249-ba03-ef9c5f37b677",
    "loc": "zz",
    "name": "xyz",
    "pres": 1000,
    "temp": 25.7,
    "windy": true
  },
  "valid": true
}

Optionally skip validation. For instance, setting token
activation in future will cause decoding to fail before
that time:
jwt encode \
	--active-in-seconds=10 \
	| jwt decode --skip-validation \
	| jq '.'
{
  "header": {
    "alg": "RS256",
    "kid": "f5949688-3787-0140-a4bf-bee3fe7d36d3",
    "typ": "JWT"
  },
  "claims": {
    "aud": "jwt-decode",
    "iat": 1643379090,
    "iss": "jwt-encode",
    "jti": "9e7f1aad-9e00-4f97-b73b-f3b83a522921",
    "nbf": 1643379100
  },
  "valid": false
}
`,
	RunE: run.Decode,
}

func init() {
	rootCmd.AddCommand(decodeCmd)
	f := decodeCmd.Flags()
	b := filepath.Base

	f.String(b(flags.KeyFile), "id.pub", "Public key file (Env: PUBLIC_KEY)")
	f.BoolP(b(flags.SkipValidation), "k", false, "Skip token validation")
}
