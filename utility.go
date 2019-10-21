package talisman

import (
	"crypto/tls"
	"github.com/rs/zerolog/log"
	"time"
)

type QuickGenerateConfig struct {
	Host           string
	AdminEmail     string
	ValidityPeriod time.Duration
	CertDir        string
	KeySize        int
}

// QuickGenerateCerts utilises the self-signed certificate generator and certificate manager to generate
// TLS certificates and check whether they already exist, or whether they expired.
// This method uses a default certs directory and an expiry of 180 days.
func QuickGenerateCerts(conf *QuickGenerateConfig) (*tls.Certificate, error) {
	var host, certBasePath, adminEmail string
	var validityPeriod time.Duration
	var keySize int
	if conf != nil {
		host = conf.Host
		certBasePath = conf.CertDir
		adminEmail = conf.AdminEmail
		validityPeriod = conf.ValidityPeriod
		keySize = conf.KeySize
	}
	if host == "" {
		host = "localhost"
	}
	if certBasePath == "" {
		certBasePath = "./certs"
	}
	if adminEmail == "" {
		adminEmail = "admin@" + host
	}
	if validityPeriod == 0 {
		validityPeriod = 180 * 24 * time.Hour
	}
	if keySize == 0 {
		keySize = 2048
	}

	// self-signed certificate generator
	certGen := SelfSignedCertificateGenerator{
		CertificateBasePath: certBasePath,
		CertificateValidity: validityPeriod,
	}

	// certificate manager
	certMan := DefaultCertificateManager{
		CertificateBasePath: certBasePath,
	}

	var keyPath, certPath string
	generateResponse, err := certGen.Generate(GenerateRequest{
		CommonName: host,
		AdminEmail: adminEmail,
		Algorithm:  RSA,
		KeySize:    keySize,
	})
	if err != nil {
		switch err.(type) {
		case CertificateExistsErr:
			inspectResponse, err := certMan.Inspect(InspectRequest{CommonName: host})
			if err != nil {
				return nil, err
			}
			if inspectResponse.Expiry.Before(time.Now()) || inspectResponse.Expiry.Equal(time.Now()) {
				log.Debug().Msgf("certificate for %s has expired", host)
				// renew
			} else if inspectResponse.Expiry.After(time.Now().Add(-7*24*time.Hour)) &&
				inspectResponse.Expiry.Before(time.Now()) {
				log.Debug().Msgf("certificate for %s is expiring soon", host)
				// renew
			}
			keyPath = inspectResponse.KeyPath
			certPath = inspectResponse.CertPath
		default:
			return nil, err
		}
	} else {
		keyPath = generateResponse.KeyPath
		certPath = generateResponse.CertPath
	}

	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &c, err
}

var Verbose bool

func DebugVerbose(msg interface{}) {
	if Verbose {
		log.Debug().Msgf("%v", msg)
	}
}
