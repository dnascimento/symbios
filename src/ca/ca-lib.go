// Package ca : Symbios Certificate Authority
// Author: Dario Nascimento
package ca

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
	"github.com/dnascimento/symbios/src/util"
)

var userCertificate *pkix.Certificate
var caKey *pkix.Key
var caCertificate *pkix.Certificate
var caInfo *pkix.CertificateAuthorityInfo
var jtiCache map[string]float64
var caIPList []string
var caDomainList []string

func init() {
	jtiCache = make(map[string]float64)
}

//NewRootCertificate creates a new certificate authority root certificate
func NewRootCertificate(keylength int, expires time.Time, organization, country string) (*pkix.Key, *pkix.Certificate, *pkix.CertificateAuthorityInfo, error) {
	cKey, err := pkix.CreateRSAKey(keylength)
	if err != nil {
		logger.Error.Printf("Failed to create root key pair: %s", err)
		return nil, nil, nil, err
	}

	caKey = cKey

	caCertificate, caInfo, err = pkix.CreateCertificateAuthority(caKey, expires, organization, country)
	if err != nil {
		logger.Error.Printf("Failed to create certificate authority: %s", err)
		return nil, nil, nil, err
	}

	return caKey, caCertificate, caInfo, nil
}

//GetCertificateFingerprint returns the fingerprint (SHA256) of root-certificate
func GetCertificateFingerprint() ([]byte, error) {
	return caCertificate.Fingerprint()
}

//GetRootCertificate returns the root-certificate encoded in PEM
func GetRootCertificate() ([]byte, error) {
	return caCertificate.Export()
}

//ValidateToken validate a token signed by the given certificate with the subject hostname
func ValidateToken(userToken string, certificate *pkix.Certificate, hostname *string) error {
	cert, err := certificate.Export()
	if err != nil {
		return err
	}

	token, err := jwt.Parse(userToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		jti := token.Claims["jti"].(string)
		if _, exists := jtiCache[jti]; exists == true {
			return nil, fmt.Errorf("Replay attack!!! jti= %s", jti)
		}
		jtiCache[jti] = token.Claims["exp"].(float64)

		//validate hostname if any
		subject := token.Claims["sub"].(string)
		if subject != "" && subject != *hostname {
			return nil, fmt.Errorf("Mismatch hostname: %s", subject)
		}

		return cert, nil
	})

	if err == nil && token.Valid {
		return nil
	}
	return fmt.Errorf("Token is invalid, %s", err)
}

//lookupUserCertificate returns the user certificate in use encoded in PEM
func lookupUserCertificate(username string) ([]byte, error) {
	return userCertificate.Export()
}

//SetUserCertificate defines the current user certificate
func SetUserCertificate(cert *pkix.Certificate) {
	//TODO multiple user
	userCertificate = cert
}

//SignCSR signs the Certificate Signing Request if the token is valid, generating a certificate with time-to-live ttl
func SignCSR(csr *pkix.CertificateSigningRequest, token string, days int) (*pkix.Certificate, error) {
	x509Csr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		return nil, err
	}

	subject := x509Csr.Subject
	commonName := subject.CommonName
	ipList := x509Csr.IPAddresses
	domainList := x509Csr.DNSNames
	fmt.Printf("\n New CSR: subject: %s \n IP List: %s \n Domains: %s \n", subject, ipList, domainList)

	if err := ValidateToken(token, userCertificate, &commonName); err != nil {
		return nil, err
	}

	ipListStr := make([]string, 10)
	for _, v := range ipList {
		s := v.String()
		ipListStr = append(ipListStr, s)
	}

	if existsInArray(ipListStr, caIPList) {
		return nil, fmt.Errorf("ALERT! Someone is trying to impersonate the CA HTTPS! Same IP: %s. ", ipList)
	}

	if existsInArray(domainList, caDomainList) {
		return nil, fmt.Errorf("ALERT! Someone is trying to impersonate the CA HTTPS! Same domain: %s. ", domainList)
	}

	certificate, err := pkix.CreateCertificateHost(caCertificate, caInfo, caKey, csr, days)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

//CreateHTTPSKeys generates a key-pair signed by the CA to be used in its HTTPS server
func CreateHTTPSKeys(outKey, outCert *string) error {
	logger.Info.Println("Creating https key")

	keyLength := 4096
	// create keys
	keys, err := pkix.CreateRSAKey(keyLength)
	if err != nil {
		return err
	}

	caIPList, caDomainList, err = util.GetHostnameAndIp()
	// create csr
	name := "ca"
	ipListStr := util.ListToString(caIPList, "")
	domainListStr := util.ListToString(caDomainList, "")
	organization := "symbios"
	country := "PT-PT"
	ttl := 2 // years

	logger.Info.Printf("HTTPS Cert with: %s  ; %s", *domainListStr, *ipListStr)

	csr, err := pkix.CreateCertificateSigningRequest(keys, name, *ipListStr, *domainListStr, organization, country)
	if err != nil {
		return err
	}

	certificate, err := pkix.CreateCertificateHost(caCertificate, caInfo, caKey, csr, ttl)

	if err := keys.SavePrivate(outKey); err != nil {
		return fmt.Errorf("Unable to save https key: %s", err)
	}

	if err := certificate.Save(outCert); err != nil {
		return fmt.Errorf("Unable to save https certificate: %s", err)
	}
	return nil
}

//existsInArray returns true if the interception of a1 and a2 is not empty
func existsInArray(a1, a2 []string) bool {
	m := make(map[string]bool)
	for _, v := range a1 {
		m[v] = true
	}

	for _, v := range a2 {
		if _, exists := m[v]; exists {
			return true
		}
	}
	return false
}
