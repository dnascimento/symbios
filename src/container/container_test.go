// Package container  - Symbios user-side client
// Author: Dario Nascimento
package container

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dnascimento/symbios/src/ca"
	"github.com/dnascimento/symbios/src/client"
	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
)

func TestContainer(t *testing.T) {
	logger.InitLogs(os.Stdout, os.Stdout, os.Stderr)
	// create root keys
	keysize := 2048
	key, err := pkix.CreateRSAKey(keysize)
	if err != nil {
		t.Fatal("Unable to generate keys.", err)
	}

	// start CA
	keylength := 4098
	organization := "org"
	country := "PT-PT"
	expiresDays := 10
	expires := time.Now().AddDate(0, 0, expiresDays).UTC()
	_, caCert, _, err := ca.NewRootCertificate(keylength, expires, organization, country)

	caFingerprint, err := caCert.Fingerprint()
	if err != nil {
		t.Fatal("Unable to generate keys.", err)
	}

	// add user to CA
	keyLength := 2048
	username := "symbios"
	userExpires := time.Now().AddDate(1, 0, 0).UTC()

	// generate private key
	_, userCert, userPrivateKey, err := client.NewUserKey(&username, keyLength, &userExpires, nil)
	if err != nil {
		t.Error(err)
	}
	ca.SetUserCertificate(userCert)
	userPrivateKeyBytes, err := userPrivateKey.ExportPrivate()
	if err != nil {
		t.Error(err)
	}

	tokenExpires := time.Duration(time.Second * 20)
	token, err := client.NewToken(userPrivateKeyBytes, username, tokenExpires)
	if err != nil {
		t.Error(err)
	}

	//setup mockHTTPServer
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /cert
		if r.URL.String() == "/v1/cert" {
			ca.HandleCertRequest(w, r)
		}
		if r.URL.String() == "/v1/csr" {
			ca.HandleCSR(w, r)
		}
	}))

	defer ts.Close()
	fmt.Println(ts.URL)

	certProp := CertificateProperties{
		name:         "Tommy",
		ip_list:      "192.168.1.1",
		domain_list:  "symbios",
		organization: "symbios",
		country:      "US",
	}

	_, err = Authenticate(&ts.URL, token, key, &certProp, &caFingerprint)
	if err != nil {
		t.Fatalf("Unable to authenticate.", err)
	}
}
