package talisman

type CertificateDoesNotExistErr struct {
	CommonName string
}

func (e CertificateDoesNotExistErr) Error() string {
	return "the certificate for '" + e.CommonName + "' does not exist"
}

type CertificateExistsErr struct {
	CommonName string
}

func (e CertificateExistsErr) Error() string {
	return "the certificate for '" + e.CommonName + "' exists"
}

type KeyDoesNotExistErr struct {
	CommonName string
}

func (e KeyDoesNotExistErr) Error() string {
	return "the private key for '" + e.CommonName + "' does not exist"
}

type KeyExistsErr struct {
	CommonName string
}

func (e KeyExistsErr) Error() string {
	return "the private key for '" + e.CommonName + "' exists"
}

type KeyTypeNotSupportedErr struct {
	Type string
}

func (e KeyTypeNotSupportedErr) Error() string {
	return "private key type '" + e.Type + "' not supported"
}

type InvalidKeySizeError struct {
}

func (e InvalidKeySizeError) Error() string {
	return "invalid key size for algorithm"
}
