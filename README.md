# jwt
Encode key-value pairs to a JWT token and decode to JSON
using private key that is encrypted using Google KMS
ensuring that the plaintext private key is never written
to the disk.

## installation
Download the code and cd to the folder, then run
```bash
go install
```

Setup autocompletion for your shell. For instance set
following for `bash`:
```bash
source <(jwt completion bash)
```

## usage
Encoding signs token using private key and decoding validates
using public key. These keys can be generated such that the
private key is Google KMS encrypted:

### keygen
```bash
jwt keygen
```
This will output two files, `id` and `id.pub` where `id` is the
private key and is encrypted using Google KMS. KMS key name and other
parameters can either be supplied on the command line or set
as env. var. Pl. see help for more details.

Google KMS encryption can be turned off using `--no-kms` flag:
```bash
jwt keygen --no-kms
```

The default keygen algorithm is RSA, however, other algorithms can
be invoked using `--alg` flag:
```bash
jwt keygen --alg=ES256
```
Pl. see help for more info on supported algorithm.

> HS256, HS384, HS512 algorithms generate a shared secret,
> which should not be encrypted using KMS. Pl. disable KMS
> when using one of these algorithms since the public keys
> are never encrypted and tool expects them to be in plaintext.

### encode
Custom key-value pairs can now be encoded to a JWT token and signed
using private key. Explicit flags are provided for a few standard
claims and certain keys are not allowed to be set such as token id.

In the most basic form a key-value can be provided as the argument
as follows:
```bash
jwt encode x=y
eyJhbGciOiJSUzI1NiIsImtpZCI6ImY1OTQ5Njg4LTM3ODctMDE0MC1hNGJmLWJlZTNmZTdkMzZkMyIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJqd3QtZGVjb2RlIiwiaWF0IjoxNjQzNDA4MTEwLCJpc3MiOiJqd3QtZW5jb2RlIiwianRpIjoiNjA5YzVlOTgtZDk2YS00MTEyLWFmY2QtMTU1Nzc5NTE4NDMyIiwieCI6InkifQ.BtcJ7P9JLyubH-WrPVoGPBYR0j02Q_10XnO4aR7weboTFiascC0029eRpm4Zt9Cdg_vidCeVKSXqpanMeCok3MfyLE77pbRlEYX98tyyhDN9HO7zX2PkKZvhENC7dxUIjP-Og7fI15StvImIhTYZ3tSIoEtr6RR-UgQ-0vqMAwCz_NmAUlCM-8gLUpGxriWYxp0iFGWfA31TFVRACg8dsnX5Anz37PGRlKj9BfAruZ6MixFvMXuCkZFyFHQOzr66ONO0vAWIqCe0kudiAJQzHgkovHK_Z32ckLeMZQvVB04wfVTRto5YMPSuCP-p5D_0aQcA8WG0g1n_Z9SFC-mLrw
```
You can inspect the token structure [here](https://jwt.io/#debugger-io?token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImY1OTQ5Njg4LTM3ODctMDE0MC1hNGJmLWJlZTNmZTdkMzZkMyIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJqd3QtZGVjb2RlIiwiaWF0IjoxNjQzNDA4MTEwLCJpc3MiOiJqd3QtZW5jb2RlIiwianRpIjoiNjA5YzVlOTgtZDk2YS00MTEyLWFmY2QtMTU1Nzc5NTE4NDMyIiwieCI6InkifQ.BtcJ7P9JLyubH-WrPVoGPBYR0j02Q_10XnO4aR7weboTFiascC0029eRpm4Zt9Cdg_vidCeVKSXqpanMeCok3MfyLE77pbRlEYX98tyyhDN9HO7zX2PkKZvhENC7dxUIjP-Og7fI15StvImIhTYZ3tSIoEtr6RR-UgQ-0vqMAwCz_NmAUlCM-8gLUpGxriWYxp0iFGWfA31TFVRACg8dsnX5Anz37PGRlKj9BfAruZ6MixFvMXuCkZFyFHQOzr66ONO0vAWIqCe0kudiAJQzHgkovHK_Z32ckLeMZQvVB04wfVTRto5YMPSuCP-p5D_0aQcA8WG0g1n_Z9SFC-mLrw)
As you see the header contains key ID which is a UUID generated from
the MD5 sum of the private key bytes (after KMS decryption as necessary).
Therefore, header key ID will always remain the same as long as the same
key is being used for signing.

The payload, however, contains token ID `jti`, which is unique to that
particular token. Each new token will have a unique token ID.

`iat` refers to issued-at-time and is denoted in seconds.

String, numbers and boolean key-values can be encoded as follows:
```bash
jwt encode \
	--str=name=xyz \
	--str=loc=zz \
	--num=temp=25.7 \
	--num=pres=1000 \
	--bool=frozen=false \
	--bool=windy=true
```

Activation and expiry times can be set relative to `now`. In the example
below the token is set to activate 10 seconds from the generation time
and expire in 100 seconds after generation. These time limits determine
token validity during decoding as discussed below.
```bash
jwt encode \
	--audience=self \
	--issuer=self \
	--active-in-seconds=10 \
	--expires-in-seconds=100
```

### decoding
Token decoding uses public key and in the example below token is passed 
via STDIN:
```bash
jwt encode \
	--str=name=xyz \
	--str=loc=zz \
	--num=temp=25.7 \
	--num=pres=1000 \
	--bool=frozen=false \
	--bool=windy=true \
	| jwt decode \
	| jq '.'
```
```json
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
```

Optionally skip validation. For instance, setting token
activation in future will cause decoding to fail before
that time:
```bash
jwt encode \
	--active-in-seconds=10 \
	| jwt decode --skip-validation \
	| jq '.'
```
```json
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
```
