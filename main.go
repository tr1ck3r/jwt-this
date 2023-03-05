package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	KEY_ID   = "firefly-ca-test-client"
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
	Configuration    string   `json:"venafi-fireflyCA.configuration,omitempty"`
	AllowedPolicies  []string `json:"venafi-fireflyCA.allowedPolicies,omitempty"`
	AllowAllPolicies bool     `json:"venafi-fireflyCA.allowAllPolicies"`
}

type Credential struct {
	Token      string
	HeaderJSON string
	ClaimsJSON string
}

func main() {
	var (
		signingKeyType string
		claims         CustomClaims
		listenPort     int
	)

	var rootCmd = &cobra.Command{
		Use:               "jwt-this",
		Version:           "1.0.0",
		Long:              "JSON Web Token (JWT) generator & JSON Web Key Set (JWKS) server for evaluating Venafi fireflyCA",
		Args:              cobra.NoArgs,
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true, DisableDefaultCmd: true},
		Run: func(cmd *cobra.Command, args []string) {
			signingKey, err := generateKeyPair(signingKeyType)
			if err != nil {
				log.Fatalf("Error: %v\n", err)
			}

			cred, err := generateToken(signingKey, &claims)
			if err != nil {
				log.Fatalf("Error: %v\n", err)
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
				log.Fatalf("Error: %v\n", err)
			}

			startJwksHttpServer(listenPort, signingKey)
		},
	}

	rootCmd.Flags().StringVarP(&signingKeyType, "key-type", "t", "ecdsa", "Signing key type, ECDSA or RSA.")
	rootCmd.Flags().StringVar(&claims.Configuration, "config-name", "", "Name of the fireflyCA Configuration for which the token is valid.")
	rootCmd.Flags().StringSliceVar(&claims.AllowedPolicies, "policy-names", []string{}, "Comma separated list of fireflyCA Policy Names for which the token is valid.")
	rootCmd.Flags().BoolVar(&claims.AllowAllPolicies, "all-policies", false, "Allow token to be used for any policy assigned to the fireflyCA Configuration.")
	rootCmd.Flags().IntVarP(&listenPort, "port", "p", 8080, "TCP port on which JWKS HTTP server will listen.")
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

func generateToken(k *SigningKeyPair, c *CustomClaims) (cred *Credential, err error) {
	var method jwt.SigningMethod

	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    "jwt-this",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}

	switch k.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		method = jwt.SigningMethodES256
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	}

	t := jwt.NewWithClaims(method, c)
	t.Header["kid"] = KEY_ID
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

func startJwksHttpServer(port int, k *SigningKeyPair) {
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
					KeyID:     KEY_ID,
					Use:       "sig",
					Algorithm: alg,
				},
			},
		}

		jwks, _ := json.MarshalIndent(set, "", "  ")
		fmt.Fprintf(w, "%s", string(jwks))
	})

	// make signing public key available at base URL
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		fmt.Fprintf(w, "%s", k.PublicKeyPEM)
	})

	fmt.Printf("JWKS URL\n========\n%s:%d%s\n\n", "http://localhost", port, JWKS_URI)
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}
