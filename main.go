package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
	OIDC_URI_PATH       = "/.well-known/openid-configuration"
	JWKS_URI_PATH       = "/.well-known/jwks.json"
	PUBLIC_KEY_FILENAME = "public-key.pem"
)

type Endpoint struct {
	Host    string
	Port    int
	UseTLS  bool
	KeyCert *[]tls.Certificate
}

type OidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
}

func main() {
	var (
		endpoint       = Endpoint{}
		signingKeyType string
		audience       string
		claims         CustomClaims
		validTime      string
	)

	var rootCmd = &cobra.Command{
		Use:               "jwt-this",
		Version:           "1.1.3",
		Long:              "JSON Web Token (JWT) generator & JSON Web Key Set (JWKS) server for evaluating Venafi Firefly",
		Args:              cobra.NoArgs,
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true, DisableDefaultCmd: true},
		Run: func(cmd *cobra.Command, args []string) {
			validity, err := time.ParseDuration(validTime)
			if err != nil {
				log.Fatalf("error: could not parse validity: %v\n", err)
			}

			err = checkPortAvailablity(endpoint.Port)
			if err != nil {
				log.Fatalf("error: port not available: %v\n", err)
			}

			signingKey, err := generateKeyPair(signingKeyType)
			if err != nil {
				log.Fatalf("error: could not generate key pair: %v\n", err)
			}

			cred, err := generateToken(signingKey, endpoint.httpURL(), audience, &claims, validity)
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

			if createTLSCertificate(&endpoint, signingKey.PublicKey, signingKey.PrivateKey) != nil {
				log.Fatalf("error: could not make self-signed TLS certificate: %v\n", err)
			}

			os.WriteFile(".trust", endpoint.tlsCertificatePEM(), 0644)
			fmt.Printf("JWKS URL:  %s\n\n", endpoint.httpURL(JWKS_URI_PATH))
			fmt.Printf("OIDC Discovery Base URL:  %s\n\n", endpoint.httpURL())

			err = startJwksHttpServer(&endpoint, signingKey)
			if err != nil {
				log.Fatalf("error: could not start JWKS HTTP server: %v\n", err)
			}
		},
	}

	rootCmd.Flags().StringVarP(&signingKeyType, "key-type", "t", "ecdsa", "Signing key type, ECDSA or RSA.")
	rootCmd.Flags().StringVarP(&audience, "audience", "a", "", "Include 'aud' claim in the JWT with the specified value.")
	rootCmd.Flags().StringVar(&claims.Configuration, "config-name", "", "Name of the Firefly Configuration for which the token is valid.")
	rootCmd.Flags().StringSliceVar(&claims.AllowedPolicies, "policy-names", []string{}, "Comma separated list of Firefly Policy Names for which the token is valid.")
	rootCmd.Flags().StringVar(&endpoint.Host, "host", getPrimaryNetAddr(), "Host to use in claim URIs.")
	rootCmd.Flags().IntVarP(&endpoint.Port, "port", "p", 8000, "TCP port on which JWKS HTTP server will listen.")
	rootCmd.Flags().BoolVar(&endpoint.UseTLS, "tls", false, "Generate a self-signed certificate and use HTTPS instead of HTTP for URLs.")
	rootCmd.Flags().StringVarP(&validTime, "validity", "v", "24h", "Duration for which the generated token will be valid.")
	rootCmd.Execute()
}

func startJwksHttpServer(e *Endpoint, k *SigningKeyPair) error {
	// make JWKS available at JWKS_URI_PATH
	http.HandleFunc(JWKS_URI_PATH, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "No-Store")
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
	http.HandleFunc(OIDC_URI_PATH, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "No-Store")
		w.Header().Set("Content-Type", "application/json")
		data := OidcDiscovery{
			Issuer:  e.httpURL(),
			JwksURI: e.httpURL(JWKS_URI_PATH),
		}
		oidc, _ := json.MarshalIndent(data, "", "  ")
		fmt.Fprintf(w, "%s", string(oidc))
	})

	// make signing public key available to download
	http.HandleFunc("/"+PUBLIC_KEY_FILENAME, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "No-Store")
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, PUBLIC_KEY_FILENAME))
		fmt.Fprintf(w, "%s", k.PublicKeyPEM)
	})

	// quick links at base URL
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "No-Store")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, homePageHTML(k.Type))
	})

	if e.KeyCert != nil {
		s := &http.Server{
			Addr:     fmt.Sprintf(":%d", e.Port),
			ErrorLog: log.New(io.Discard, "", log.LstdFlags),
			Handler:  nil,
			TLSConfig: &tls.Config{
				Certificates: *e.KeyCert,
			},
		}
		return s.ListenAndServeTLS("", "")
	}
	return http.ListenAndServe(fmt.Sprintf(":%d", e.Port), nil)
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
		return "127.0.0.1" // localhost
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func homePageHTML(keyType string) string {
	return fmt.Sprintf(`
<html>
<head>
  <title>jwt-this</title>
  <style>
    . { font-family: arial }
    a { text-decoration: none }
    a:hover { text-decoration: underline }
  </style>
</head>
<body>
  <h1>jwt-this</h1>
  <ul>
    <li><a href="%s">JSON Web Key Set (JWKS)</a></li>
    <li><a href="%s">OpenID Connect (OIDC) Configuration</a></li>
    <li><a href="/%s">Public Key [%s]</a></li>
  </ul>
  <a href="https://github.com/tr1ck3r/jwt-this#readme">README</a> |
  <a href="https://github.com/tr1ck3r/jwt-this/releases/latest">Latest Release</a> |
  <a href="https://hub.docker.com/r/tr1ck3r/jwt-this">Container Image</a>
</body>
</html>
`, JWKS_URI_PATH, OIDC_URI_PATH, PUBLIC_KEY_FILENAME, strings.Replace(keyType, "_", " ", 1))
}

func (e *Endpoint) httpURL(path ...string) string {
	protocol := "http"
	if e.UseTLS {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", protocol, e.Host, e.Port, strings.Join(path, "/"))
}

func (e *Endpoint) tlsCertificatePEM() []byte {
	if e.KeyCert != nil {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: (*e.KeyCert)[0].Certificate[0],
		})
	}
	return nil
}
