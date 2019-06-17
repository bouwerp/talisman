package talisman

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/bouwerp/log"
	"math/big"
	"os"
	"strings"
	"syscall"
	"time"
)

type SelfSignedCertificateGenerator struct {
	CertificateBasePath string
	CertificateValidity time.Duration
}

func (c SelfSignedCertificateGenerator) Renew(RenewRequest) (*RenewResponse, error) {
	panic("implement me")
}

func (c SelfSignedCertificateGenerator) Revoke(RevokeRequest) (*RevokeResponse, error) {
	panic("implement me")
}

func (c SelfSignedCertificateGenerator) Generate(request GenerateRequest) (*GenerateResponse, error) {
	// create certs directory
	certBasePath := strings.TrimRight(c.CertificateBasePath, string(os.PathSeparator))
	_, err := os.Stat(certBasePath)
	if err != nil {
		if (err.(*os.PathError)).Err == syscall.ENOENT {
			// create the dir
			err := os.Mkdir(certBasePath, 0740)
			if err != nil {
				log.Error("could not create certs directory:", err)
				return nil, err
			}
		} else {
			log.Error("could not create certs directory:", err)
			return nil, err
		}
	}
	certPath := strings.Join([]string{certBasePath, request.CommonName + ".pem"}, string(os.PathSeparator))
	keyPath := strings.Join([]string{certBasePath, request.CommonName + "-key.pem"}, string(os.PathSeparator))

	_, err = os.Stat(certPath)
	if err != nil {
		if (err.(*os.PathError)).Err == syscall.ENOENT {
			// should't exist
		} else {
			log.Error("could not create public key:", err)
			return nil, err
		}
	} else {
		return nil, CertificateExistsErr{CommonName: request.CommonName}
	}
	_, err = os.Stat(keyPath)
	if err != nil {
		if (err.(*os.PathError)).Err == syscall.ENOENT {
			// should't exist
		} else {
			log.Error("could not create private key:", err)
			return nil, err
		}
	} else {
		return nil, KeyExistsErr{CommonName: request.CommonName}
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(c.CertificateValidity)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Error("failed to generate serial number:", err)
		return nil, err
	}

	template := x509.Certificate{
		DNSNames:     []string{request.CommonName},
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ionoverse"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		EmailAddresses:        []string{request.AdminEmail},
	}

	hosts := []string{request.CommonName}
	template.DNSNames = hosts
	template.Subject.CommonName = request.CommonName

	template.IsCA = false
	template.KeyUsage |= x509.KeyUsageKeyEncipherment
	template.KeyUsage |= x509.KeyUsageCertSign
	template.KeyUsage |= x509.KeyUsageCRLSign

	// select the algorithm for the private key based on the request
	var theKey interface{}
	var theDerBytes []byte
	switch request.Algorithm {
	case ECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			log.Error("failed to generate ECDSA private key:", err)
			return nil, err
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			log.Error("failed to generate ECDSA certificate:", err)
			return nil, err
		}
		theKey = key
		theDerBytes = derBytes
	case RSA:
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Error("failed to generate RSA private key:", err)
			return nil, err
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			log.Error("failed to generate RSA certificate:", err)
			return nil, err
		}
		theKey = key
		theDerBytes = derBytes
	default:
		// TODO typed error
		return nil, errors.New("unsupported algorithm")
	}

	// generate the certificate and key files
	certOut, err := os.Create(certPath)
	if err != nil {
		log.Error("failed to open cert for writing:", err)
		return nil, err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: theDerBytes}); err != nil {
		log.Error("failed to write data to cert:", err)
		return nil, err
	}
	if err := certOut.Close(); err != nil {
		log.Error("error closing cert:", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Error("failed to open key for writing:", err)
		return nil, err
	}
	pemBlock, err := pemBlockForKey(theKey)
	if err != nil {
		log.Error("failed to get pem key block:", err)
		return nil, err
	}
	if err := pem.Encode(keyOut, pemBlock); err != nil {
		log.Error("failed to write data to key:", err)
		return nil, err
	}
	if err := keyOut.Close(); err != nil {
		log.Error("error closing key:", err)
		return nil, err
	}
	return &GenerateResponse{
		KeyPath:  keyPath,
		CertPath: certPath,
	}, nil
}

func pemBlockForKey(key interface{}) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Error("Unable to marshal ECDSA private key:v", err)
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, nil
	}
}
