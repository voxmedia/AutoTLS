# Let’s Encrypt

Let’s Encrypt is a certificate authority that provides free SSL certificates for public websites. To use an ACME command line tool to request certificates manually, you do not need to have a Let's Encrypt aaccount, but you will need one to use this tool. To generate an account key manually, run the following commands:

## Registering a Let’s Encrypt Account Key with `acme.sh`

```bash
# install `acme.sh`
curl https://get.acme.sh | sh

# verify installation
~/.acme.sh/acme.sh --version

# set Let’s Encrypt as the default certificate authority
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

# register against Let’s Encrypt **staging** (safe for tests) with an RSA account key
~/.acme.sh/acme.sh --register-account \
    --server https://acme-staging-v02.api.letsencrypt.org/directory \
    -m your.email@example.com \
    --accountkeylength 4096

# verify account files
ls -la ~/.acme.sh/ca/acme-staging-v02.api.letsencrypt.org/directory/
cat ~/.acme.sh/ca/acme-staging-v02.api.letsencrypt.org/directory/account.json
```

`account.json` should look like this (truncated for readability):

```json
{
  "key": {
    "kty": "RSA",
	"n": "....",      // big base64url modulus
	"e": "AQAB",      // public exponent, usually 65537
	"d": "....",      // private exponent
	"p": "....",      // prime factor 1
	"q": "....",      // prime factor 2
	"dp": "....",     // d mod (p-1)
	"dq": "....",     // d mod (q-1)
	"qi": "...."      // inverse of q mod p
 },
  "createdAt": "2025-08-21T21:56:17.612047646Z",
  "status": "valid"
}
```

The `"key"` section is your **Let’s Encrypt account key** (for staging):

```json
{"kty": "RSA", "n": "....", "e": "AQAB", "d": "....", "p": "....", "q": "....", "dp": "....", "dq": "....", "qi": "...."}
```

> [!NOTE]
> Store this key securely in your chosen secrets manager. The name you use to store it under will be the value you need to populate `LE_ACCOUNT_KEY_SECRET_NAME` in your `.env` file.

When you're ready, repeat the process for production:

```bash
~/.acme.sh/acme.sh --register-account \
  --server https://acme-v02.api.letsencrypt.org/directory \
  -m your.email@example.com \
  --accountkeylength 4096

ls -la ~/.acme.sh/ca/acme-v02.api.letsencrypt.org/directory/
cat ~/.acme.sh/ca/acme-v02.api.letsencrypt.org/directory/account.json
```


