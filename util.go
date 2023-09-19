package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	random "math/rand"
	"net"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateKeyPair(signingKeyType, tlsServerName string) (keyPair *SigningKeyPair, tlsKeyCert *[]tls.Certificate, err error) {
	switch strings.ToLower(signingKeyType) {

	case "ecdsa":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, nil, err
		}
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}

		keyPair = &SigningKeyPair{
			Type:          "EC_P256",
			PublicKey:     &privateKey.PublicKey,
			PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privateKeyBytes})),
			PrivateKey:    privateKey,
			PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: publicKeyBytes})),
		}

		tlsKeyCert, err = tlsCertSelfSigned(tlsServerName, &privateKey.PublicKey, privateKey)
		if err != nil {
			return nil, nil, err
		}
		return keyPair, tlsKeyCert, nil

	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, nil, err
		}
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}

		keyPair = &SigningKeyPair{
			Type:          "RSA_2048",
			PublicKey:     &privateKey.PublicKey,
			PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privateKeyBytes})),
			PrivateKey:    privateKey,
			PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: publicKeyBytes})),
		}

		tlsKeyCert, err = tlsCertSelfSigned(tlsServerName, &privateKey.PublicKey, privateKey)
		if err != nil {
			return nil, nil, err
		}
		return keyPair, tlsKeyCert, nil
	}

	return nil, nil, fmt.Errorf("invalid signing key type: %s", signingKeyType)
}

func generateToken(k *SigningKeyPair, issuer, audience string, c *CustomClaims, validity time.Duration) (cred *Credential, err error) {
	var method jwt.SigningMethod

	c.RegisteredClaims = jwt.RegisteredClaims{
		Subject:   "jwt-this",
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

func tlsCertSelfSigned(name string, publicKey any, privateKey any) (keyCert *[]tls.Certificate, err error) {

	sanValue, _ := asn1.Marshal([]asn1.RawValue{{Tag: 2 /* dNSName */, Class: 2, Bytes: []byte(name)}})
	ip := net.ParseIP(name)
	if ip != nil && ip.To4() != nil {
		sanValue, _ = asn1.Marshal([]asn1.RawValue{{Tag: 7 /* iPAddress */, Class: 2, Bytes: []byte(ip.To4())}})
	}

	template := x509.Certificate{
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 17}, // subject alternative name
				Critical: true,
				Value:    sanValue,
			},
		},
		Subject:      pkix.Name{CommonName: "jwt-this"},
		Issuer:       pkix.Name{CommonName: "jwt-this"},
		SerialNumber: big.NewInt(random.Int63()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed TLS certificate: %v", err)
	}
	keyCert = &[]tls.Certificate{
		{
			Certificate: [][]byte{certBytes},
			PrivateKey:  privateKey,
		},
	}
	return keyCert, nil
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
