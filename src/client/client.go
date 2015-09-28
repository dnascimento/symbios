/*
*  Symbios Server
*  Author: Dario Nascimento
 */
package client

import (
	"crypto/tls"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dnascimento/symbios/src/logger"
	"github.com/dnascimento/symbios/src/pkix"
)

// NewUserKey generates a new user RSA key, stores it in disk and returns its base64 encoding
func NewUserKey(username *string, keyLength int, expires *time.Time, out *string) (*string, *pkix.Certificate, *pkix.Key, error) {
	//logger.Info.Printf("New User Key: %d bits, user: %s", keyLength, *username)

	// generate keys
	keys, err := pkix.CreateRSAKey(keyLength)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to create key:", err)
	}

	// create user self-signed certificate
	userCert, err := pkix.CreateUserCertificate(keys, *username, *expires)

	if out != nil {
		if err := keys.SavePrivate(out); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to write private key:", err)
		}

		certOut := (*out) + ".crt"
		if err := userCert.Save(&certOut); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to write public key certificate:", err)
		}
	}

	// encode public key
	encodedCertificate, err := userCert.EncodeBase64()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode user certificate:", err)
	}

	return encodedCertificate, userCert, keys, nil
}

//NewTokenUsingPrivateKeyFile reads a RSA private key file and signs a new JWT token with it
func NewTokenUsingPrivateKeyFile(privateKeyPath string, hostname string, expires time.Duration) (*string, error) {
	//logger.Info.Printf("new token, key: %s", privateKeyPath)

	privateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		logger.Error.Print("failed to read private key file:", err)
		return nil, err
	}

	return NewToken(privateKey, hostname, expires)
}

//NewToken generates a new JWT token and signs using a RSA private key
func NewToken(privateKey []byte, hostname string, expires time.Duration) (*string, error) {

	// create token
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims["iss"] = "symbios"
	token.Claims["sub"] = hostname
	//aud audience
	token.Claims["nbf"] = time.Now()
	token.Claims["iat"] = time.Now()
	token.Claims["exp"] = time.Now().Add(expires).Unix()
	token.Claims["jti"] = time.Now()

	tokenString, err := token.SignedString(privateKey)
	return &tokenString, err
}

func GetCACertHash(endpoint *string) (*[]byte, error) {
	//logger.Info.Printf("get ca certificate at: %s", *endpoint)
	// ignore TLS because we don't know the destination yet
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Get(fmt.Sprintf("%s/v1/hash", *endpoint))
	if err != nil {
		log.Fatal("A problem occurred during communication with the Symbios CA.", err)
		return nil, err
	}
	// read the response body and get it into certificate form
	defer res.Body.Close()
	hashBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal("A problem occurred while reading the hash of CA certificate from the Symbios CA. ", err)
		return nil, err
	}
	return &hashBytes, nil
}

func GetCACertHashEncoded(endpoint *string) (*string, error) {
	hash, err := GetCACertHash(endpoint)
	if err != nil {
		return nil, err
	}

	encoded := b64.StdEncoding.EncodeToString(*hash)
	return &encoded, nil
}
