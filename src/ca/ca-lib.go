/*
*  Symbios Server
*  Author: Dario Nascimento
 */
package ca

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
)

var userCertificate *pkix.Certificate
var caKey *pkix.Key
var caCertificate *pkix.Certificate
var caInfo *pkix.CertificateAuthorityInfo
var jtiCache map[string]float64

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

func ValidateToken(userToken string, certificate *pkix.Certificate) error {
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
	if err := ValidateToken(token, userCertificate); err != nil {
		return nil, err
	}

	certificate, err := pkix.CreateCertificateHost(caCertificate, caInfo, caKey, csr, ttl)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}
