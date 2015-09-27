/*
*  Symbios Certificate Authority
*  Author: Dario Nascimento
 */
package ca

import (
	b64 "encoding/base64"
	"strconv"
)

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
)

func HttpServer(port int, userKey string, keylength int, organization string, country string, expires time.Time) error {

	// read user pubKey
	certificate, err := readUserCertificate(userKey)
	if err != nil {
		logger.Error.Printf("failed to read user certificate:", err)
		os.Exit(2)
	}

	_, _, _, err = NewRootCertificate(keylength, expires, organization, country)
	if err != nil {
		logger.Error.Printf("failed to create root certificate:", err)
		return err
	}

	SetUserCertificate(certificate)

	// start HTTP server
	http.HandleFunc("/v1/hash", HandleCertFingerprintRequest)
	http.HandleFunc("/v1/cert", HandleCertRequest)
	http.HandleFunc("/v1/csr", HandleCSR)
	logger.Info.Printf("Symbios Certificate Authority listening in port: %s", port)
	err = http.ListenAndServe(":"+strconv.Itoa(port), nil)
	if err != nil {
		logger.Error.Println(err)
	}
	return nil
}

func HandleCertFingerprintRequest(w http.ResponseWriter, req *http.Request) {
	//logger.Info.Printf("Cert Hash")
	fingerprint, err := GetCertificateFingerprint()
	if err != nil {
		logger.Error.Printf("%s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(fingerprint)
}

func HandleCertRequest(w http.ResponseWriter, req *http.Request) {
	logger.Info.Printf("Request CA certificate")
	cert, err := GetRootCertificate()
	if err != nil {
		logger.Error.Printf("%s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write(cert)
	return
}

func HandleCSR(w http.ResponseWriter, req *http.Request) {
	// make sure its post
	if req.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "No POST:", req.Method)
		return
	}

	// Delay answer to delay attacks
	time.Sleep(1000 * time.Millisecond)

	token := req.Header.Get("X-Auth-Token")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "No Token.")
		return
	}

	// get CSR
	rawCsr, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Error.Printf("%s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	csr, err := pkix.NewCertificateSigningRequestFromPEM(rawCsr)
	if err != nil {
		logger.Error.Printf("%s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//TODO
	ttl := 25
	cert, err := SignCSR(csr, token, ttl)
	if err != nil {
		logger.Error.Printf("%s\n", err.Error())
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	certificateBytes, err := cert.Export()
	if err != nil {
		logger.Error.Printf("%s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(certificateBytes)
}

func readUserCertificate(encodedUserKey string) (*pkix.Certificate, error) {
	if len(encodedUserKey) == 0 {
		return nil, errors.New("user key is required")
	}
	userCertificateBytes, err := b64.StdEncoding.DecodeString(encodedUserKey)
	if err != nil {
		logger.Error.Printf("failed to decode certificate:", err)
		return nil, err
	}

	// convert to KeyPair
	cert, err := pkix.NewCertificateFromPEM(userCertificateBytes)
	if err != nil {
		logger.Error.Printf("failed to create certificate:", err)
		return nil, err
	}
	return cert, nil
}
