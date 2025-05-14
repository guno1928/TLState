package TLState

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/curve25519"
)

var (
	ErrFailedDecodePemCert = errors.New("failed to decode PEM certificate")
	ErrFailedDecodePemKey  = errors.New("failed to decode PEM key")
)

type Config struct {
	ParsedCert        *x509.Certificate
	ParsedKey         crypto.Signer
	PrivateKey        []byte
	PublicKey         []byte
	ServerCert        []byte
	ServerKey         []byte
	CertificateRecord []byte
	Ciphers           []CipherSuite
}

func ConfigFromFile(certPath, keyPath string) (*Config, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, ErrFailedDecodePemCert
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, ErrFailedDecodePemKey
	}
	return ConfigFromDER(certBlock.Bytes, keyBlock.Bytes)
}

func ConfigFromDER(serverCert, serverKey []byte) (*Config, error) {
	privateKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(serverCert)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	if rsaKey, err := x509.ParsePKCS1PrivateKey(serverKey); err == nil {
		signer = rsaKey
	} else if pk8Key, err := x509.ParsePKCS8PrivateKey(serverKey); err == nil {
		if s, ok := pk8Key.(crypto.Signer); ok {
			signer = s
		} else {
			return nil, ErrFailedDecodePemKey
		}
	} else if ecKey, err := x509.ParseECPrivateKey(serverKey); err == nil {
		signer = ecKey
	} else {
		return nil, ErrFailedDecodePemKey
	}

	config := Config{
		ParsedCert: cert,
		ParsedKey:  signer,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ServerCert: serverCert,
		ServerKey:  serverKey,
		Ciphers:    []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256},
	}
	config.createCertificateRecord()
	return &config, nil
}

func (c *Config) createCertificateRecord() {

	certMsg := []byte{
		0x00,
	}

	certEntryLen := 3 + len(c.ServerCert) + 2

	certMsg = append(certMsg,
		byte(certEntryLen>>16),
		byte(certEntryLen>>8),
		byte(certEntryLen))

	certMsg = append(certMsg,
		byte(len(c.ServerCert)>>16),
		byte(len(c.ServerCert)>>8),
		byte(len(c.ServerCert)))
	certMsg = append(certMsg, c.ServerCert...)

	certMsg = append(certMsg, 0x00, 0x00)

	c.CertificateRecord = certMsg
}