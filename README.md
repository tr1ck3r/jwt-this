# jwt-this

**jwt-this** is a command line utility I created to simplify demonstration, evaluation, and
simple testing with *Venafi fireflyCA*.  When run, it generates a new signing key pair,
uses it to sign and output a new JSON Web Token (JWT) containing specified *fireflyCA*-related
claims, and starts a basic HTTP server (listening on port 8080 by default) where the
signing public key is published via a JSON Web Key Set (JWKS).  

Use the JWT as the `Bearer` token value for the `Authorization` header required when requesting
certificates from *fireflyCA* via gRPC, GraphQL, or REST.  Make sure the *fireflyCA* has network
access to the JWKS endpoint and use the appropriate URL in the *fireflyCA* Configuration (replace
"localhost" in the output URL with the FQDN or IP address of the host *fireflyCA* can reach,
e.g., http://172.16.1.123:8080/.well-known/jwks.json).

## Examples

Get a JWT signed by an EC_P256 key pair for requesting certificates from a *fireflyCA* using 
a Configuration named "Demo Config" and allows certificate requests using either Policies called
"Demo Policy 1" or "Demo Policy 2":
```sh
jwt-this --config-name "Demo Config" --policy-names "Demo Policy 1","Demo Policy 2"
```

Get a JWT signed by an RSA_2048 key pair for requesting certificates from a *fireflyCA* using
a Configuration named "Eval Config" and allows certificate requests using any policy associated
with the *fireflyCA* configuration, and serve up the JWKS on port 12345:
```sh
jwt-this -p 12345 -t rsa --config-name "Eval Config" --all-policies
```

### Sample Output
`CLI`
```
Token
=====
eyJhbGciOiJFUzI1NiIsImtpZCI6ImZpcmVmbHktY2EtdGVzdC1jbGllbnQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJqd3QtdGhpcyIsImV4cCI6MTY3ODA2NTcxNCwiaWF0IjoxNjc3OTc5MzE0LCJ2ZW5hZmktZmlyZWZseUNBLmNvbmZpZ3VyYXRpb24iOiJEZW1vIENvbmZpZyIsInZlbmFmaS1maXJlZmx5Q0EuYWxsb3dlZFBvbGljaWVzIjpbIkRlbW8gUG9saWN5IDEiLCJEZW1vIFBvbGljeSAyIl0sInZlbmFmaS1maXJlZmx5Q0EuYWxsb3dBbGxQb2xpY2llcyI6ZmFsc2V9.8494nS-J7Ff9dBJgCwArxuJzWM3ZkXp_Ez2sxE-62M0MsxhSSvbjXHjBxGyF3VsgL1kNrdY7uCv2DUujLu3GFg

Header
======
{
  "alg": "ES256",
  "kid": "firefly-ca-test-client",
  "typ": "JWT"
}

Claims
======
{
  "iss": "jwt-this",
  "exp": 1678065714,
  "iat": 1677979314,
  "venafi-fireflyCA.configuration": "Demo Config",
  "venafi-fireflyCA.allowedPolicies": [
    "Demo Policy 1",
    "Demo Policy 2"
  ],
  "venafi-fireflyCA.allowAllPolicies": false
}

JWKS URL
========
http://localhost:8080/.well-known/jwks.json
```

`GET http://localhost:8080/.well-known/jwks.json`
```json
{
  "keys": [
    {
      "use": "sig",
      "kty": "EC",
      "kid": "firefly-ca-test-client",
      "crv": "P-256",
      "alg": "ES256",
      "x": "rM3pET9w2z8p0TTlOREvt9PPQ_IRpZuXZUlgP5n-PDQ",
      "y": "KwXGtbtly6P_0ywb-ceNCwVAZM-oxNOaraIDHVhN9GM"
    }
  ]
}
```

### Help
```
JSON Web Token (JWT) generator & JSON Web Key Set (JWKS) server for evaluating Venafi fireflyCA

Usage:
  jwt-this [flags]

Flags:
      --all-policies           Allow token to be used for any policy assigned to the fireflyCA Configuration.
      --config-name string     Name of the fireflyCA Configuration for which the token is valid.
  -h, --help                   help for jwt-this
  -t, --key-type string        Signing key type, ECDSA or RSA. (default "ecdsa")
      --policy-names strings   Comma separated list of fireflyCA Policy Names for which the token is valid.
  -p, --port int               TCP port on which JWKS HTTP server will listen. (default 8080)
  -v, --version                version for jwt-this
```