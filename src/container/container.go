package container

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
)

//CertificateProperties TODO
type CertificateProperties struct {
	name         string
	ip_list      string
	domain_list  string
	organization string
	country      string
}

//AuthenticateAndSave generates a key, creates a CSR, sends to CA and stores the generated private key and certificate
func AuthenticateAndSave(endpoint, token, keyOut, crtOut, caCertOut *string, keysize int, cn, ipList, domain_list, organization, country *string, caCertificateHash *[]byte) error {
	key, err := pkix.CreateRSAKey(keysize)
	if err != nil {
		logger.Error.Printf("Unable to generate keys.", err)
		return err
	}

	certProp := CertificateProperties{
		name:         *cn,
		ip_list:      *ipList,
		domain_list:  *domain_list,
		organization: *organization,
		country:      *country,
	}

	cert, err := Authenticate(endpoint, token, key, &certProp, caCertificateHash)
	if err != nil {
		return fmt.Errorf("Unable to authenticate.", err)
	}

	if err := key.SavePrivate(keyOut); err != nil {
		return fmt.Errorf("Unable to save key:", err)
	}

	if err := cert.Save(crtOut); err != nil {
		return fmt.Errorf("Unable to save certificate:", err)
	}

	caCert, err := GetCACertificate(endpoint)
	if err != nil {
		return fmt.Errorf("Unable to get CA Certificate.", err)
	}

	if err := caCert.Save(caCertOut); err != nil {
		return fmt.Errorf("Unable to save CA certificate:", err)
	}

	return nil
}

func Authenticate(endpoint *string, token *string, containerKey *pkix.Key, certProp *CertificateProperties, caCertificateHash *[]byte) (*pkix.Certificate, error) {
	logger.Info.Printf("Authenticating token %s on CA %s", *token, *endpoint)

	caCertificate, err := GetCACertificate(endpoint)
	if err != nil {
		return nil, err
	}

	err = caCertificate.VerifyFingerprint(caCertificateHash)
	if err != nil {
		return nil, fmt.Errorf("Invalid CA certificate")
	}

	// Add CA certificate to CertPool
	pool := x509.NewCertPool()
	rawCaCert, err := caCertificate.Export()
	if err != nil {
		return nil, err
	}
	pool.AppendCertsFromPEM(rawCaCert)

	// Generate a CSR
	csr, err := pkix.CreateCertificateSigningRequest(containerKey, certProp.name, certProp.ip_list,
		certProp.domain_list, certProp.organization, certProp.country)

	if err != nil {
		return nil, err
	}

	// PEM encode the CSR
	pemCSR, err := csr.Export()
	if err != nil {
		return nil, err
	}

	// set HTTPS client
	var client *http.Client
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{RootCAs: pool},
		DisableCompression: true,
	}
	client = &http.Client{
		Transport: tr,
	}

	// Fetch a signed certificate
	crt, err := sendCSR(client, pemCSR, token, endpoint)
	if err != nil {
		return nil, err
	}

	return crt, err
}

func sendCSR(client *http.Client, csr []byte, token *string, endpoint *string) (*pkix.Certificate, error) {
	if csr == nil {
		return nil, fmt.Errorf("csr is nil")
	}
	if token == nil {
		return nil, fmt.Errorf("token is nil")
	}
	if endpoint == nil {
		return nil, fmt.Errorf("endpoint is nil")
	}

	// Execute a POST request to upload the provided CSR
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/csr", *endpoint), bytes.NewReader(csr))
	if err != nil {
		return nil, fmt.Errorf("Unable to form the HTTPS request.", err)
	}
	req.Header.Set("X-Auth-Token", *token)
	signTimeStart := time.Now()
	res, err := client.Do(req)
	logger.Info.Printf("[TIMER] [%s] Uploaded CSR and retrieved CRT.", time.Since(signTimeStart))
	if err != nil {
		return nil, fmt.Errorf("A problem occurred during communication with the Symbios CA.", err)
	}

	// read the response body and get it into certificate form
	logger.Info.Printf("CRT received: %d ", req.ContentLength)
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)

	fmt.Println(res.Status)
	if res.Status != "200 OK" {
		return nil, fmt.Errorf(string(data))
	}

	if err != nil {
		return nil, fmt.Errorf("A problem occurred while reading the certificate from the Symbios CA. ", err)
	}

	cert, err := pkix.NewCertificateFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("A problem occurred while parsing the certificate from the Symbios CA. ", err)
	}

	return cert, nil
}

func CheckCertificate(hostCert *pkix.Certificate, hostname string, rootCertificate *pkix.Certificate) error {
	err := rootCertificate.VerifyHost(hostCert, hostname)
	return err
}

func ExportCACert(endpoint *string, out *string) error {
	cert, err := GetCACertificate(endpoint)
	if err != nil {
		return err
	}

	if err := cert.Save(out); err != nil {
		return fmt.Errorf("Unable to save CA certificate:", err)
	}

	return nil

}

func GetCACertificate(endpoint *string) (*pkix.Certificate, error) {
	logger.Info.Printf("Get CA Certificate")
	res, err := http.Get(fmt.Sprintf("%s/v1/cert", *endpoint))
	if err != nil {
		return nil, fmt.Errorf("A problem occurred during communication with the Symbios CA.", err)
	}
	// read the response body and get it into certificate form
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("A problem occurred while reading the CA certificate from the Symbios CA. ", err)
	}
	cert, err := pkix.NewCertificateFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("A problem occurred while converting the CA certificate from the Symbios CA. ", err)
	}
	return cert, err
}
