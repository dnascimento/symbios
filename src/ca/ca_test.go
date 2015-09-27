// Certificate authority test package
package ca

import (
	"os"
	"testing"
	"time"

	"github.com/dnascimento/symbios/src/logger"
)

//token validation is tested in client_test.go

func TestCa(t *testing.T) {
	logger.InitLogs(os.Stdout, os.Stdout, os.Stderr)
	keylength := 4098
	organization := "org"
	country := "PT-PT"
	expiresDays := 10
	expires := time.Now().AddDate(0, 0, expiresDays).UTC()

	// generate certificate
	_, rootCert, _, err := NewRootCertificate(keylength, expires, organization, country)
	if err != nil {
		t.Error(err)
	}

	// verify fingerprint
	fingerprint, err := GetCertificateFingerprint()
	if err != nil {
		t.Error(err)
	}

	if err := rootCert.VerifyFingerprint(&fingerprint); err != nil {
		t.Fatalf("Fingerprint!", err)
	}

	// CSR signature is tested in container_test.go

}
