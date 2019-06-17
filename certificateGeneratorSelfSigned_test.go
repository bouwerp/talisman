package talisman

import (
	"fmt"
	"testing"
)

func TestSelfSignedCertificateGenerator_Generate(t *testing.T) {
	certGen := SelfSignedCertificateGenerator{CertificateBasePath: "./certs"}
	genResponse, err := certGen.Generate(GenerateRequest{
		CommonName: "test1",
		AdminEmail: "admin@test1.com",
		Algorithm:  RSA,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(genResponse.KeyPath)
}
