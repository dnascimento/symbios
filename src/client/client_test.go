package client

import (
	"bytes"
	b64 "encoding/base64"
	"io/ioutil"
)

import (
	"os"
	"testing"
	"time"

	"github.com/dnascimento/symbios/src/ca"
	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
)

func TestClient(t *testing.T) {
	logger.InitLogs(os.Stdout, os.Stdout, os.Stderr)

	keyLength := 2048
	username := "symbios"
	privateKeyPath := "id_test"
	expires := time.Now().AddDate(1, 0, 0).UTC()

	// generate private key
	userKeyBase64, _, _, err := NewUserKey(&username, keyLength, &expires, &privateKeyPath)
	if err != nil {
		t.Error(err)
	}
	pubKeyPath := privateKeyPath + ".crt"

	defer os.Remove(privateKeyPath)
	defer os.Remove(pubKeyPath)

	// compare generated public key and base64encoded key
	userKey, err := b64.StdEncoding.DecodeString(*userKeyBase64)
	if err != nil {
		t.Error(err)
	}

	rawCsr, err := ioutil.ReadFile(pubKeyPath)

	if !bytes.Equal(userKey, rawCsr) {
		t.Fail()
	}

	userCert, err := pkix.NewCertificateFromPEM(rawCsr)
	if err != nil {
		t.Error(err)
	}

	tokenExpires := time.Duration(time.Second * 10)

	// generate token using private key
	userToken, err := NewTokenUsingPrivateKeyFile(privateKeyPath, username, &tokenExpires)
	if err != nil {
		t.Error(err)
	}

	if err := ca.ValidateToken(*userToken, userCert); err != nil {
		t.Fatalf("Token validation failed: %s", err)
	}

	// replay attack
	if err := ca.ValidateToken(*userToken, userCert); err == nil {
		t.Fatalf("Replay attack detection fail: %s", err)
	}

	// expired token
	tokenExpires = time.Duration(time.Second * 1)
	userToken, err = NewTokenUsingPrivateKeyFile(privateKeyPath, username, &tokenExpires)
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Duration(time.Second * 5))

	if err := ca.ValidateToken(*userToken, userCert); err == nil {
		t.Fatalf("Expired token detection fail: %s", err)
	}

}
