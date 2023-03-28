# jwt-this

**jwt-this** is a command line utility I created to simplify demonstration, evaluation, and
simple testing with *Venafi Firefly*.  When run, it generates a new signing key pair,
uses it to sign and output a new JSON Web Token (JWT) containing specified *Firefly*-related
claims, and starts a basic HTTP server (listening on port 8000 by default) where the
signing public key is published via a JSON Web Key Set (JWKS) so it can be used by *fireflyCA* 
to verify the signature of the JWT.  

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

Get a JWT signed by an RSA_2048 key pair for requesting certificates from a *Firefly* using
a Configuration named "Eval Config" and allows certificate requests using any policy associated
with the *Firefly* configuration, and serve up the JWKS on port 12345:
```sh
jwt-this -p 12345 -t rsa --config-name "Eval Config" --all-policies
```

### Output Samples
`CLI`
```
Token
=====
eyJhbGciOiJFUzI1NiIsImtpZCI6ImZpcmVmbHktdGVzdC1jbGllbnQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJqd3QtdGhpcyIsImV4cCI6MTY4MDEwNjI3OSwiaWF0IjoxNjgwMDE5ODc5LCJ2ZW5hZmktZmlyZWZseS5jb25maWd1cmF0aW9uIjoiRGVtbyBDb25maWciLCJ2ZW5hZmktZmlyZWZseS5hbGxvd2VkUG9saWNpZXMiOlsiRGVtbyBQb2xpY3kgMSIsIkRlbW8gUG9saWN5IDIiXSwidmVuYWZpLWZpcmVmbHkuYWxsb3dBbGxQb2xpY2llcyI6ZmFsc2V9.cbtDvM-6MYCqd36Z3HzBO9h9Rx7BVa9ATCvvzsVOzoKuBy35uhQkiYREkUVK65dunMQS9RksCgRypveZWFOSBg

Header
======
{
  "alg": "ES256",
  "kid": "firefly-test-client",
  "typ": "JWT"
}

Claims
======
{
  "iss": "jwt-this",
  "exp": 1680106279,
  "iat": 1680019879,
  "venafi-firefly.configuration": "Demo Config",
  "venafi-firefly.allowedPolicies": [
    "Demo Policy 1",
    "Demo Policy 2"
  ],
  "venafi-firefly.allowAllPolicies": false
}

JWKS URL
========
http://172.16.1.123:8000/.well-known/jwks.json
```

`GET http://localhost:8080/.well-known/jwks.json`
```json
{
  "keys": [
    {
      "use": "sig",
      "kty": "EC",
      "kid": "firefly-test-client",
      "crv": "P-256",
      "alg": "ES256",
      "x": "rM3pET9w2z8p0TTlOREvt9PPQ_IRpZuXZUlgP5n-PDQ",
      "y": "KwXGtbtly6P_0ywb-ceNCwVAZM-oxNOaraIDHVhN9GM"
    }
  ]
}
```

## Help
```
JSON Web Token (JWT) generator & JSON Web Key Set (JWKS) server for evaluating Venafi Firefly

Usage:
  jwt-this [flags]

Flags:
      --all-policies           Allow token to be used for any policy assigned to the Firefly Configuration.
      --config-name string     Name of the Firefly Configuration for which the token is valid.
  -h, --help                   help for jwt-this
  -t, --key-type string        Signing key type, ECDSA or RSA. (default "ecdsa")
      --policy-names strings   Comma separated list of Firefly Policy Names for which the token is valid.
  -p, --port int               TCP port on which JWKS HTTP server will listen. (default 8000)
  -v, --validity string        Duration for which the generated token will be valid. (default "24h")
      --version                version for jwt-this
```