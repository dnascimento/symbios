/*
*  Symbios Server
*  Author: Dario Nascimento
 */
package ca

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dnascimento/symbios/src/container"
	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
)

var userCertificate *pkix.Certificate
var caKey *pkix.Key
var caCertificate *pkix.Certificate
var caInfo *pkix.CertificateAuthorityInfo
var jtiCache map[string]float64
var caIpList []string
var caDomainList []string

func init() {
	jtiCache = make(map[string]float64)
}

func NewRootCertificate(keylength int, expires time.Time, organization, country string) (*pkix.Key, *pkix.Certificate, *pkix.CertificateAuthorityInfo, error) {
	cKey, err := pkix.CreateRSAKey(keylength)
	if err != nil {
		logger.Error.Printf("Failed to create root key pair:", err)
		return nil, nil, nil, err
	}

	caKey = cKey

	caCertificate, caInfo, err = pkix.CreateCertificateAuthority(caKey, expires, organization, country)
	if err != nil {
		logger.Error.Printf("Failed to create certificate authority:", err)
		return nil, nil, nil, err
	}

	return caKey, caCertificate, caInfo, nil
}

func GetCertificateFingerprint() ([]byte, error) {
	return caCertificate.Fingerprint()
}

func GetRootCertificate() ([]byte, error) {
	return caCertificate.Export()
}

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
	} else {
		return fmt.Errorf("Token is invalid, %s", err)
	}
}

func lookupUserCertificate(username string) ([]byte, error) {
	return userCertificate.Export()
}

func SetUserCertificate(cert *pkix.Certificate) {
	//TODO multiple user
	userCertificate = cert
}

func SignCSR(csr *pkix.CertificateSigningRequest, token string, ttl int) (*pkix.Certificate, error) {
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

	if existsInArray(ipListStr, caIpList) {
		return nil, fmt.Errorf("ALERT! Someone is trying to impersonate the CA HTTPS! Same IP: %s. ", ipList)
	}

	if existsInArray(domainList, caDomainList) {
		return nil, fmt.Errorf("ALERT! Someone is trying to impersonate the CA HTTPS! Same domain: %s. ", domainList)
	}

	certificate, err := pkix.CreateCertificateHost(caCertificate, caInfo, caKey, csr, ttl)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func CreateHttpsKeys(outKey, outCert *string) error {
	logger.Info.Println("Creating https key")

	keyLength := 4096
	// create keys
	keys, err := pkix.CreateRSAKey(keyLength)
	if err != nil {
		return err
	}

	caIpList, caDomainList, err = container.GetHostnameAndIp()
	// create csr
	name := "ca"
	ipListStr := container.ListToString(caIpList, "")
	domainListStr := container.ListToString(caDomainList, "")
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
		return fmt.Errorf("Unable to save https key:", err)
	}

	if err := certificate.Save(outCert); err != nil {
		return fmt.Errorf("Unable to save https certificate:", err)
	}
	return nil
}

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
