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
