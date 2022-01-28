/*
Copyright © 2022 kubetrail.io authors

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
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubetrail/jwt/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "jwt",
	Short: "CLI to encode and decode JWT tokens",
	Long: `CLI to encode/sign and decode/validate JWT tokens

* Generate various JWT signing keys that are
  encrypted by default using Google KMS or 
  optionally not encrypted.
* Sign JWT tokens using these keys optionally
  encoding key=value pairs as claims.
* Decode JWT tokens using public keys and 
  optionally skip validation
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	f := rootCmd.PersistentFlags()
	b := filepath.Base

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.jwt.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	f.String(b(flags.GoogleProjectID), "", "Google project ID (Env: GOOGLE_PROJECT_ID)")
	f.String(b(flags.GoogleApplicationCredentials), "", "Google app credentials (Env: GOOGLE_APPLICATION_CREDENTIALS)")
	f.String(b(flags.KmsLocation), "global", "KMS location (Env: KMS_LOCATION)")
	f.String(b(flags.KmsKeyring), "", "KMS keyring name (Env: KMS_KEYRING)")
	f.String(b(flags.KmsKey), "", "KMS key name (Env: KMS_KEY)")
	f.Bool(b(flags.NoKms), false, "Do not use KMS")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".jwt" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".jwt")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
