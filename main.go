package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	KEY_ID   = "firefly-test-client"
	OIDC_URI = "/.well-known/openid-configuration"
	JWKS_URI = "/.well-known/jwks.json"
)

type SigningKeyPair struct {
	Type          string
	PublicKey     interface{}
	PublicKeyPEM  string
	PrivateKey    interface{}
	PrivateKeyPEM string
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Configuration    string   `json:"venafi-firefly.configuration,omitempty"`
	AllowedPolicies  []string `json:"venafi-firefly.allowedPolicies,omitempty"`
	AllowAllPolicies bool     `json:"venafi-firefly.allowAllPolicies"`
}

type Credential struct {
	Token      string
	HeaderJSON string
	ClaimsJSON string
}

type OidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}

func main() {
	var (
		signingKeyType string
		audience       string
		claims         CustomClaims
		host           string
		listenPort     int
		validTime      string
	)

	var rootCmd = &cobra.Command{
		Use:               "jwt-this",
		Version:           "1.0.4",
		Long:              "JSON Web Token (JWT) generator & JSON Web Key Set (JWKS) server for evaluating Venafi Firefly",
		Args:              cobra.NoArgs,
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true, DisableDefaultCmd: true},
		Run: func(cmd *cobra.Command, args []string) {
			validity, err := time.ParseDuration(validTime)
			if err != nil {
				log.Fatalf("error: could not parse validity: %v\n", err)
			}

			err = checkPortAvailablity(listenPort)
			if err != nil {
				log.Fatalf("error: port not available: %v\n", err)
			}

			signingKey, err := generateKeyPair(signingKeyType)
			if err != nil {
				log.Fatalf("error: could not generate key pair: %v\n", err)
			}

			issuer := fmt.Sprintf("http://%s:%d", host, listenPort)

			cred, err := generateToken(signingKey, issuer, audience, &claims, validity)
			if err != nil {
				log.Fatalf("error: could not generate token: %v\n", err)
			}

			os.WriteFile(".token", []byte(cred.Token), 0644)
			fmt.Printf("Token\n=====\n%s\n\n", cred.Token)
			fmt.Printf("Header\n======\n%s\n\n", cred.HeaderJSON)
			fmt.Printf("Claims\n======\n%s\n\n", cred.ClaimsJSON)

			// verify the signature
			_, err = jwt.Parse(cred.Token, func(token *jwt.Token) (interface{}, error) {
				return signingKey.PublicKey, nil
			})
			if err != nil {
				log.Fatalf("error: could not verify token signature: %v\n", err)
			}

			fmt.Printf("JWKS URL\n========\n%s%s\n\n", issuer, JWKS_URI)

			err = startJwksHttpServer(listenPort, issuer, signingKey)
			if err != nil {
				log.Fatalf("error: could not start JWKS HTTP server: %v\n", err)
			}

		},
	}

	rootCmd.Flags().StringVarP(&signingKeyType, "key-type", "t", "ecdsa", "Signing key type, ECDSA or RSA.")
	rootCmd.Flags().StringVarP(&audience, "audience", "a", "", "Include 'aud' claim in the JWT with the specified value.")
	rootCmd.Flags().StringVar(&claims.Configuration, "config-name", "", "Name of the Firefly Configuration for which the token is valid.")
	rootCmd.Flags().StringSliceVar(&claims.AllowedPolicies, "policy-names", []string{}, "Comma separated list of Firefly Policy Names for which the token is valid.")
	rootCmd.Flags().BoolVar(&claims.AllowAllPolicies, "all-policies", false, "Allow token to be used for any policy assigned to the Firefly Configuration.")
	rootCmd.Flags().StringVar(&host, "host", getPrimaryNetAddr(), "Host to use in claim URIs.")
	rootCmd.Flags().IntVarP(&listenPort, "port", "p", 8000, "TCP port on which JWKS HTTP server will listen.")
	rootCmd.Flags().StringVarP(&validTime, "validity", "v", "24h", "Duration for which the generated token will be valid.")
	rootCmd.Execute()
}

func generateKeyPair(signingKeyType string) (keyPair *SigningKeyPair, err error) {
	switch strings.ToLower(signingKeyType) {

	case "ecdsa":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		keyPair = &SigningKeyPair{
			Type:          "EC_P256",
			PublicKey:     &privateKey.PublicKey,
			PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privateKeyBytes})),
			PrivateKey:    privateKey,
			PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: publicKeyBytes})),
		}
		return keyPair, nil

	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		keyPair = &SigningKeyPair{
			Type:          "RSA_2048",
			PublicKey:     &privateKey.PublicKey,
			PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privateKeyBytes})),
			PrivateKey:    privateKey,
			PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: publicKeyBytes})),
		}
		return keyPair, nil
	}

	return nil, fmt.Errorf("invalid signing key type: %s", signingKeyType)
}

func generateToken(k *SigningKeyPair, issuer, audience string, c *CustomClaims, validity time.Duration) (cred *Credential, err error) {
	var method jwt.SigningMethod

	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(validity)),
	}
	if audience != "" {
		c.RegisteredClaims.Audience = jwt.ClaimStrings{audience}
	}

	switch k.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		method = jwt.SigningMethodES256
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	}

	t := jwt.NewWithClaims(method, c)
	t.Header["kid"] = jwkThumbprint(k.PublicKey)
	token, err := t.SignedString(k.PrivateKey)
	if err != nil {
		return
	}

	headerBytes, _ := json.MarshalIndent(t.Header, "", "  ")
	claimsBytes, _ := json.MarshalIndent(t.Claims, "", "  ")

	cred = &Credential{
		Token:      token,
		HeaderJSON: string(headerBytes),
		ClaimsJSON: string(claimsBytes),
	}
	return
}

func startJwksHttpServer(port int, issuer string, k *SigningKeyPair) error {
	// make JWKS available at JWKS_URL
	http.HandleFunc(JWKS_URI, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var alg string
		switch k.PublicKey.(type) {
		case *ecdsa.PublicKey:
			alg = "ES256"
		case *rsa.PublicKey:
			alg = "RS256"
		}

		set := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       k.PublicKey,
					KeyID:     jwkThumbprint(k.PublicKey),
					Use:       "sig",
					Algorithm: alg,
				},
			},
		}

		jwks, _ := json.MarshalIndent(set, "", "  ")
		fmt.Fprintf(w, "%s", string(jwks))
	})

	// make JWKS URL known through OIDC Discovery
	http.HandleFunc(OIDC_URI, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := OidcDiscovery{
			Issuer:  issuer,
			JwksUri: issuer + JWKS_URI,
		}
		oidc, _ := json.MarshalIndent(data, "", "  ")
		fmt.Fprintf(w, "%s", string(oidc))
	})

	// make signing public key available at base URL
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		fmt.Fprintf(w, "%s", k.PublicKeyPEM)
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

// JWK SHA-256 thumbprint per RFC 7638
func jwkThumbprint(publicKey interface{}) string {
	h := crypto.SHA256.New()

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		fmt.Fprintf(h, `{"crv":"%s"`, k.Curve.Params().Name)
		fmt.Fprintf(h, `,"kty":"EC"`)
		fmt.Fprintf(h, `,"x":"%s"`, base64.RawURLEncoding.EncodeToString(k.X.Bytes()))
		fmt.Fprintf(h, `,"y":"%s"}`, base64.RawURLEncoding.EncodeToString(k.Y.Bytes()))
	case *rsa.PublicKey:
		data := make([]byte, 8)
		binary.BigEndian.PutUint64(data, uint64(k.E))
		i := 0
		for ; i < len(data); i++ {
			if data[i] != 0x0 { // need to trim leading zeros
				break
			}
		}
		fmt.Fprintf(h, `{"e":"%s"`, base64.RawURLEncoding.EncodeToString(data[i:]))
		fmt.Fprintf(h, `,"kty":"RSA"`)
		fmt.Fprintf(h, `,"n":"%s"}`, base64.RawURLEncoding.EncodeToString(k.N.Bytes()))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func checkPortAvailablity(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		listener.Close()
	}
	return err
}

func getPrimaryNetAddr() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
