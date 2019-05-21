package tls

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

type GenerateRequest struct {
	CommonName string
	AdminEmail string
}

type GenerateResponse struct {
	CertPath string
	KeyPath  string
}
