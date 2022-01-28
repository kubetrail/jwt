package flags

const (
	GoogleProjectID              = "google-project-id"              // Google KMS project ID
	KmsLocation                  = "kms-location"                   // KMS location for the key and keyring
	KmsKeyring                   = "kms-keyring"                    // KMS keyring name
	KmsKey                       = "kms-key"                        // KMS key name
	GoogleApplicationCredentials = "google-application-credentials" // Google service account with KMS encrypter/decrypter role
	KeyFile                      = "key"                            // key file name
	SkipValidation               = "skip-validation"                // Do not validate JWT using public key
	Issuer                       = "issuer"
	ExpiresInSeconds             = "expires-in-seconds"
	ActiveInSeconds              = "active-in-seconds"
	Audience                     = "audience"
	Subject                      = "subject"
	NoKms                        = "no-kms" // do not use KMS
	Alg                          = "alg"    // algorithm
	Str                          = "str"    // string value for a key-value pair
	Num                          = "num"    // number value for a key-value pair
	Bool                         = "bool"   // boolean value for a key-value pair
)
