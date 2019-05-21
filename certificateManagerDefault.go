package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/bouwerp/log"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

type DefaultCertificateManager struct {
	CertificateBasePath string
}

func (c DefaultCertificateManager) Inspect(request InspectRequest) (*InspectResponse, error) { // construct cert and private key paths
	certBasePath := strings.TrimRight(c.CertificateBasePath, string(os.PathSeparator))
	certPath := strings.Join([]string{certBasePath, request.CommonName + ".pem"}, string(os.PathSeparator))
	keyPath := strings.Join([]string{certBasePath, request.CommonName + "-key.pem"}, string(os.PathSeparator))

	// read cert and key
	certFile, err := os.Open(certPath)
	if err != nil {
		log.Error("could not load certificate:", err)
		return nil, err
	}
	keFile, err := os.Open(keyPath)
	if err != nil {
		log.Error("could not load key:", err)
		return nil, err
	}

	certBytes, err := ioutil.ReadAll(certFile)
	if err != nil {
		log.Error("could not read certificate:", err)
		return nil, err
	}
	keyBytes, err := ioutil.ReadAll(keFile)
	if err != nil {
		log.Error("could not read key:", err)
		return nil, err
	}

	certBlock, rest := pem.Decode(certBytes)
	if len(rest) > 0 {
		log.Error("malformed certificate")
		return nil, err
	}
	keyBlock, rest := pem.Decode(keyBytes)
	if len(rest) > 0 {
		log.Error("malformed key")
		return nil, err
	}

	// parse the private key
	keyType := regexp.MustCompile("\\s+").Split(keyBlock.Type, -1)[0]
	var bitSize int
	switch keyType {
	case "EC":
		var pk *ecdsa.PrivateKey
		pk, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Error("could not parse key:", err)
			return nil, err
		}
		bitSize = pk.Params().BitSize
	case "RSA":
		var pk *rsa.PrivateKey
		pk, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Error("could not parse key:", err)
			return nil, err
		}
		bitSize = pk.Size()
	default:
		return nil, KeyTypeNotSupportedErr{Type: keyType}
	}

	// parse the certificate
	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Error("could not parse certificate:", err)
		return nil, err
	}

	return &InspectResponse{
		KeyType:    keyType,
		KeyBitSize: bitSize,
		Subject:    cert.Subject.String(),
		Signature:  hex.EncodeToString(cert.Signature),
		Emails:     cert.EmailAddresses,
		Expiry:     cert.NotAfter,
		CertPath:   certPath,
		KeyPath:    keyPath,
	}, nil
}
