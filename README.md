# tls

Go library for managing TLS certificates. Currently, only a self-signed certificate
implementation exists.

# Example

An example of using the certificate generator and manager is shown in the following example.

Instantiate the generator and manager:
```go
// self-signed certificate generator
certGen := security.SelfSignedCertificateGenerator{
    CertificateBasePath: "./certs",
    CertificateValidity: 5 * 365 * 25 * time.Hour,
}

// certificate manager
certMan := security.DefaultCertificateManager{
    CertificateBasePath: "./certs",
}
```

These are then used together to generate new and inspect existing certificates.
```go
...
keyPath := ""
certPath := ""
generateResponse, err := certGen.Generate(security.GenerateRequest{
    CommonName: host,
    AdminEmail: "admin@" + host,
})
if err != nil {
    switch err.(type) {
    case security.CertificateExistsErr:
        inspectResponse, err := certMan.Inspect(security.InspectRequest{CommonName: host})
        if err != nil {
            log.Error("could not load certificates:", err)
            os.Exit(1)
        }
        // check expiry and decide if renewal is necessary
        if inspectResponse.Expiry.Before(time.Now()) || inspectResponse.Expiry.Equal(time.Now()) {
            log.Debug("certificate for", host, "has expired")
        } else if inspectResponse.Expiry.After(time.Now().Add(-7*24*time.Hour)) &&
            inspectResponse.Expiry.Before(time.Now()) {
            log.Debug("certificate for", host, "is expiring soon")
        }
        keyPath = inspectResponse.KeyPath
        certPath = inspectResponse.CertPath
    default:
        log.Error("could not generate certs:", err)
        os.Exit(1)
    }
} else {
    keyPath = generateResponse.KeyPath
    certPath = generateResponse.CertPath
}

// load the PEM encoded public and private key into a X.509 encoded certificate
cert, err := tls.LoadX509KeyPair(certPath, keyPath)

if err != nil {
    log.Debug(err)
    os.Exit(1)
}
// this can then be used in a TLS configuration for a TCP or HTTP server, for example.
tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
...
```