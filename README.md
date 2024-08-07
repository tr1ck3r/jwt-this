# jwt-this

**jwt-this** (pronounced "jot this") is a command line utility I created to simplify
demonstration, evaluation, and simple testing with [*Venafi Firefly*](https://venafi.com/firefly/).
When run, it generates a new signing key pair, uses it to sign and output a new JSON Web Token
(JWT) containing specified *Firefly*-related claims, and starts a basic HTTP server (listening on
port 8000 by default) where the signing public key is published via a JSON Web Key Set (JWKS) so it
can be used by *Firefly* to verify the signature of the JWT.

Use the JWT as the `Bearer` token value for the `Authorization` header required when requesting
certificates from *Firefly* via gRPC, GraphQL, or REST.  Make sure the *Firefly* has network
access to the JWKS endpoint and use the appropriate URL in the *Firefly* Configuration (use `--host`
when running `jwt-this` to specify a hostname, FQDN or IP address *Firefly* can reach).

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
jwt-this -p 12345 -t rsa -v 5m30s --config-name "Eval Config"
```

### Output Samples
`CLI`
```
Token
=====
eyJhbGciOiJFUzI1NiIsImtpZCI6IjY1MkQxeVFKVWZWRGduSmFFbzNMNEluQnNldDRsQlA1NG4xSzAxMnB0WlkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwOi8vMTAuMjAuMzAuNDA6ODAwMCIsInN1YiI6Imp3dC10aGlzIiwiZXhwIjoxNjk1MDc2ODI0LCJpYXQiOjE2OTQ5OTA0MjQsInZlbmFmaS1maXJlZmx5LmNvbmZpZ3VyYXRpb24iOiJEZW1vIENvbmZpZyIsInZlbmFmaS1maXJlZmx5LmFsbG93ZWRQb2xpY2llcyI6WyJEZW1vIFBvbGljeSAxIiwiRGVtbyBQb2xpY3kgMiJdLCJ2ZW5hZmktZmlyZWZseS5hbGxvd0FsbFBvbGljaWVzIjpmYWxzZX0.a64ugg4It-Pcq6--WsG6rt3BjjL_V38S_IHIx2cMiFSiqEwCJcNNXP4nkDD33jdXVOS3Iaivo8UtjK4xctQr7g

Header
======
{
  "alg": "ES256",
  "kid": "652D1yQJUfVDgnJaEo3L4InBset4lBP54n1K012ptZY",
  "typ": "JWT"
}

Claims
======
{
  "iss": "http://10.20.30.40:8000",
  "sub": "jwt-this",
  "exp": 1695076824,
  "iat": 1694990424,
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
      "kid": "652D1yQJUfVDgnJaEo3L4InBset4lBP54n1K012ptZY",
      "crv": "P-256",
      "alg": "ES256",
      "x": "9GPhULzc0i8R6r7j5CQvz_TEId57cFEC93oaSqLy5_w",
      "y": "05BKmW0A1s0tdjzmJ0YJhhWfy0U5inxbo21FFyBGwpM"
    }
  ]
}
```
`GET http://10.20.30.40:8000/.well-known/openid-configuration`
```json
{
  "issuer": "http://10.20.30.40:8000",
  "token_endpoint": "http://10.20.30.40:8000/token",
  "jwks_uri": "http://10.20.30.40:8000/.well-known/jwks.json",
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "venafi-firefly.configuration",
    "venafi-firefly.allowedPolicies",
    "venafi-firefly.allowAllPolicies"
  ]
}
```
`GET http://10.20.30.40:8000/`

![jwt-this home page](homepage.png)


## Help
```
JSON Web Token (JWT) generator & JSON Web Key Set (JWKS) server for evaluating Venafi Firefly

Usage:
  jwt-this [flags]

Flags:
  -a, --audience string        Include 'aud' claim in the JWT with the specified value.
      --config-name string     Name of the Firefly Configuration for which the token is valid.
  -h, --help                   help for jwt-this
      --host string            Host to use in claim URIs. (default <host-primary-ip>)
  -t, --key-type string        Signing key type, ECDSA or RSA. (default "ecdsa")
      --policy-names strings   Comma separated list of Firefly Policy Names for which the token is valid.
  -p, --port int               TCP port on which JWKS HTTP server will listen. (default 8000)
      --tls                    Generate a self-signed certificate and use HTTPS instead of HTTP for URLs.
  -u, --url string             Ignore --host, --port, and protocol derived from --tls and use this URL instead for claim URIs.
  -v, --validity string        Duration for which the generated token will be valid. (default "24h")
      --version                version for jwt-this
```

## Venafi Firefly Claims

By default, *Firefly* looks for claims prefixed by `venafi-firefly` in JWTs presented by its API clients.
It can be challenging or undesirable to define such claims using some enterprise identity providers, so it is 
possible to configure *Firefly* v1.4.1 (and higher) to look for alternative configuration and policy claim
names. `jwt-this` can be used to simulate this situation by setting the following environment variables:

| Environment Variable       | Default Name                      |
|----------------------------|-----------------------------------|
| `CLAIM_CONFIGURATION`      | `venafi-firefly.configuration`    |
| `CLAIM_ALLOWED_POLICIES`   | `venafi-firefly.allowedPolicies`  |
| `CLAIM_ALLOW_ALL_POLICIES` | `venafi-firefly.allowAllPolicies` |

The value of these claims (and whether they're present in JWTs at all) is still determined by the 
`--config-name` and `--policy-name` command line parameters.

## Arbitrary Custom Claims

The `/token` endpoint supports generating JWTs that include arbitrary custom claims when invoked via `POST`.
Specify claim name-value pairs using a payload appropriate for the `application/x-www-form-urlencoded`
HTTP content type.  For example, to get a JWT that includes `name`, `role`, and `email` custom claims
using `curl`:

```sh
curl -d "name=John+Doe&role=Administrator&email=john.doe@company.example" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -X POST http://10.20.30.40:8000/token
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

Special thanks to [@MattiasGees](https://github.com/MattiasGees) for contributing the
[Dockerfile](Dockerfile) and [Makefile](Makefile) :clap:
