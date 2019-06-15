package talisman

type CertificateGenerator interface {
	Generate(GenerateRequest) (*GenerateResponse, error)
	Revoke(RevokeRequest) (*RevokeResponse, error)
	Renew(RenewRequest) (*RenewResponse, error)
}

type RevokeRequest struct {
	CommonName string
}

type RevokeResponse struct {
}

type RenewRequest struct {
	CommonName string
}

type RenewResponse struct {
}

type AlgorithmType string

const ECDSA AlgorithmType = "ECDSA"
const RSA AlgorithmType = "RSA"

type GenerateRequest struct {
	CommonName string
	AdminEmail string
	Algorithm  AlgorithmType
}

type GenerateResponse struct {
	CertPath string
	KeyPath  string
}
