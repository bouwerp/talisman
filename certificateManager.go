package talisman

import "time"

type CertificateManager interface {
	Inspect(InspectRequest) (*InspectResponse, error)
}

type InspectRequest struct {
	CommonName string
}

type InspectResponse struct {
	KeyType    string
	KeyBitSize int
	Subject    string
	Signature  string
	Emails     []string
	Expiry     time.Time
	CertPath   string
	KeyPath    string
}
