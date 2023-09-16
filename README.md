# jwt-this

**jwt-this** (pronounced "jot this") is a command line utility I created to simplify
demonstration, evaluation, and simple testing with *Venafi Firefly*.  When run, it generates
a new signing key pair, uses it to sign and output a new JSON Web Token (JWT) containing
specified *Firefly*-related claims, and starts a basic HTTP server (listening on port 8000 by
default) where the signing public key is published via a JSON Web Key Set (JWKS) so it can be
used by *Firefly* to verify the signature of the JWT.  

Use the JWT as the `Bearer` token value for the `Authorization` header required when requesting
certificates from *Firefly* via gRPC, GraphQL, or REST.  Make sure the *Firefly* has network
access to the JWKS endpoint and use the appropriate URL in the *Firefly* Configuration (replace
"localhost" in the output URL with the FQDN or IP address of the host *Firefly* can reach,
e.g., http://172.16.1.123:8000/.well-known/jwks.json).

## Examples

Get a JWT signed by an EC_P256 key pair for requesting certificates from a *Firefly* using 
a Configuration named "Demo Config" and allows certificate requests using either Policies called
"Demo Policy 1" or "Demo Policy 2":
```sh
jwt-this --config-name "Demo Config" --policy-names "Demo Policy 1","Demo Policy 2"
```

Get a JWT signed by an RSA_2048 key pair and valid for 5 minutes 30 seconds that can be used
to request certificates from a *Firefly* using a Configuration named "Eval Config" and allows
certificate requests using any policy associated with the *Firefly* configuration, and serve up
the JWKS on port 12345:
```sh
jwt-this -p 12345 -t rsa -v 5m30s --config-name "Eval Config" --all-policies
```

### Output Samples
`CLI`
```
Token
=====
eyJhbGciOiJFUzI1NiIsImtpZCI6IjZnX1hQZGJWT08tWi1rSTc1UE04Z2U5eFJsUWZUZW9NVmFUYmgtNy1kNXMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwOi8vMTkyLjE2OC4wLjIzMzo4MDAwIiwic3ViIjoiand0LXRoaXMiLCJleHAiOjE2OTQ5OTE5ODMsImlhdCI6MTY5NDkwNTU4MywidmVuYWZpLWZpcmVmbHkuYWxsb3dBbGxQb2xpY2llcyI6ZmFsc2V9.5vJFux40E3sMEDy8R9zzDbz4ofZTwtPz3UOiAMkOhjXpfaR-9-sChsduKXoRmL9bzoHLXgz5XcpZiELTYFTPLg

Header
======
{
  "alg": "ES256",
  "kid": "6g_XPdbVOO-Z-kI75PM8ge9xRlQfTeoMVaTbh-7-d5s",
  "typ": "JWT"
}

Claims
======
{
  "iss": "http://10.20.30.40:8000",
  "sub": "jwt-this",
  "exp": 1694991983,
  "iat": 1694905583,
  "venafi-firefly.configuration": "Demo Config",
  "venafi-firefly.allowedPolicies": [
    "Demo Policy 1",
    "Demo Policy 2"
  ],
  "venafi-firefly.allowAllPolicies": false
}

JWKS URL:  http://10.20.30.40:8000/.well-known/jwks.json

OIDC Discovery Base URL:  http://10.20.30.40:8000
```

`GET http://10.20.30.40:8000/.well-known/jwks.json`
```json
{
  "keys": [
    {
      "use": "sig",
      "kty": "EC",
      "kid": "6g_XPdbVOO-Z-kI75PM8ge9xRlQfTeoMVaTbh-7-d5s",
      "crv": "P-256",
      "alg": "ES256",
      "x": "Tl6Sw3nWq2DtSAwC8vxrB0BKRtxHoStifBhrS_iJ0fg",
      "y": "xa6ACpNO7tktt29nKP5du6DhUMewhVH_-S7XRyp1fSk"
    }
  ]
}
```
`GET http://10.20.30.40:8000/.well-known/openid-configuration`
```json
{
  "issuer": "http://10.20.30.40:8000",
  "jwks_uri": "http://10.20.30.40:8000/.well-known/jwks.json"
}
```
## Help
```
JSON Web Token (JWT) generator & JSON Web Key Set (JWKS) server for evaluating Venafi Firefly

Usage:
  jwt-this [flags]

Flags:
      --all-policies           Allow token to be used for any policy assigned to the Firefly Configuration.
  -a, --audience string        Include 'aud' claim in the JWT with the specified value.
      --config-name string     Name of the Firefly Configuration for which the token is valid.
  -h, --help                   help for jwt-this
      --host string            Host to use in claim URIs. (default "192.168.0.233")
  -t, --key-type string        Signing key type, ECDSA or RSA. (default "ecdsa")
      --policy-names strings   Comma separated list of Firefly Policy Names for which the token is valid.
  -p, --port int               TCP port on which JWKS HTTP server will listen. (default 8000)
  -v, --validity string        Duration for which the generated token will be valid. (default "24h")
      --version                version for jwt-this
```

## Running as a Container

It may be more convenient in some cases to run `jwt-this` as container so I've built and published a
container image to [Docker Hub](https://hub.docker.com/r/tr1ck3r/jwt-this).  You can use the following
`docker-compose.yml` to run `jwt-this` using [Docker Compose](https://docs.docker.com/compose/):
``` yaml
services:
  jwt-this:
    image: "tr1ck3r/jwt-this:latest"
    ports:
      - "8000:8000"
    command: --config-name "Demo Config" --policy-names "Demo Policy 1","Demo Policy 2"
```

Special thanks to @MattiasGees for contributing the [Dockerfile](Dockerfile) and [Makefile](Makefile) :clap:
