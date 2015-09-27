// Package main parses the command, subcommand and flags and invokes.
package main

import (
	b64 "encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dnascimento/symbios/src/ca"
	"github.com/dnascimento/symbios/src/client"
	"github.com/dnascimento/symbios/src/container"
	"github.com/dnascimento/symbios/src/logger"
)

const daysInTenYears = 3650
const defaultTokenDuration = time.Duration(time.Minute * 10) //10 minutes

func main() {
	logger.InitLogs(os.Stdout, os.Stdout, os.Stderr)

	if len(os.Args) == 1 {
		argError("")
		return
	}

	switch os.Args[1] {
	case "client":
		clientCmd()
	case "ca":
		caCmd()
	case "container":
		containerCmd()
	default:
		error := fmt.Sprintf("%q is not valid command.\n", os.Args[1])
		argError(error)
		os.Exit(2)
	}
}

// Client Commands
func clientCmd() {
	// new-user
	var newUserCmd = flag.NewFlagSet("new-user", flag.ExitOnError)
	var keyLength = newUserCmd.Int("size", 4096, "User key size")
	var username = newUserCmd.String("username", "user", "Username")
	var out = newUserCmd.String("out", "id_rsa", "Key output file")
	var expiresDays = newUserCmd.Int("days", daysInTenYears, "User key expires after (days)")
	var expires = time.Now().AddDate(0, 0, *expiresDays).UTC()

	// new-token
	var newTokenCmd = flag.NewFlagSet("new-token", flag.ExitOnError)
	var newTokenUsername = newTokenCmd.String("username", "user", "Username")
	var privateKeyPath = newTokenCmd.String("key", "id_rsa", "Private key file")

	// ca-hash
	var caHashCmd = flag.NewFlagSet("ca-hash", flag.ExitOnError)
	var caHost = caHashCmd.String("host", "localhost", "Certificate Authority hostname")
	var caPort = caHashCmd.String("port", "33004", "Certificate Authority port")

	// select subcommand
	switch os.Args[2] {
	case "new-user":
		newUserCmd.Parse(os.Args[3:])
		encodedCert, _, _, err := client.NewUserKey(username, *keyLength, &expires, out)
		if err != nil {
			logger.Error.Printf("Failed to create new user key: %s", err)
			os.Exit(2)
		}
		fmt.Println(*encodedCert)

	case "new-token":
		newTokenCmd.Parse(os.Args[3:])
		token, err := client.NewTokenUsingPrivateKeyFile(*privateKeyPath, *newTokenUsername, defaultTokenDuration)
		if err != nil {
			logger.Error.Printf("Failed to create token: %s", err)
			os.Exit(2)
		}
		fmt.Println(*token)

	case "ca-hash":
		caHashCmd.Parse(os.Args[3:])
		endpoint := "http://" + (*caHost) + ":" + (*caPort)
		hash, err := client.GetCACertHashEncoded(&endpoint)
		if err != nil {
			logger.Error.Printf("Failed to get CA Hash: %s", err)
			os.Exit(2)
		}
		fmt.Println(*hash)

	default:
		error := fmt.Sprintf("%q is not valid command.\n", os.Args[1])
		argError(error)
		os.Exit(2)
	}
}

// Certificate Authority Commands
func caCmd() {
	var caCmd = flag.NewFlagSet("ca", flag.ExitOnError)
	var port = caCmd.Int("port", 33004, "Default port for Symbios CA.")
	var userKey = caCmd.String("user-key", "", "base64 encoded certificate")
	// var userKeyfile = caCmd.String("key-file", "", "user key path")
	var keylength = caCmd.Int("key-size", 4098, "RSA key length")
	var organization = caCmd.String("organization", "org", "organization")
	var country = caCmd.String("country", "PT-PT", "country")
	var expiresDays = caCmd.Int("days", daysInTenYears, "User key expires after (days)")
	var expires = time.Now().AddDate(0, 0, *expiresDays).UTC()

	caCmd.Parse(os.Args[2:])

	if err := ca.HttpServer(*port, *userKey, *keylength, *organization, *country, expires); err != nil {
		logger.Error.Printf("Failed to start Certificate Authority HTTP Server: %s", err)
		os.Exit(2)
	}
}

// Container Commands
func containerCmd() {
	var containerCmd = flag.NewFlagSet("container", flag.ExitOnError)

	var caHost = containerCmd.String("host", "localhost", "Certificate Authority hostname")
	var caPort = containerCmd.String("port", "33004", "Certificate Authority port")

	var token = containerCmd.String("token", "", "User's provisioning token.")
	var caHashEncoded = containerCmd.String("ca-hash", "", "User's provisioning token.")

	var keyOut = containerCmd.String("keyout", "/etc/secret/key", "The location where the client private and public key will be written.")
	var crtOut = containerCmd.String("certout", "/etc/secret/client-cert.pem", "The location where the client certificate will be written.")
	var caCertOut = containerCmd.String("ca-cert-out", "/etc/secret/ca-cert.pem", "The location where the ca certificate will be written.")
	var keysize = containerCmd.Int("size", 2048, "The size of the private key e.g. 1024, 2048 (default), 4096 .")

	var cn = containerCmd.String("cn", "Tommy", "Default common name.")
	var ip_list = containerCmd.String("ip_list", "192.168.1.1", "IP List.")
	var domain_list = containerCmd.String("domain_list", "symbios", "Domain List.")
	var organization = containerCmd.String("organization", "symbios", "Organization.")
	var country = containerCmd.String("country", "US", "Country.")

	containerCmd.Parse(os.Args[2:])

	endpoint := "http://" + (*caHost) + ":" + (*caPort)

	if *caHashEncoded == "" || *token == "" {
		logger.Error.Printf("-ca-hash -token are required fields")
		os.Exit(2)
	}
	caHash, err := b64.StdEncoding.DecodeString(*caHashEncoded)
	if err != nil {
		logger.Error.Printf("Decode CA Certificate Fingerprint: %s", err)
		os.Exit(2)
	}

	if err := container.AuthenticateAndSave(&endpoint, token, keyOut, crtOut, caCertOut, *keysize, cn, ip_list, domain_list, organization, country, &caHash); err != nil {
		logger.Error.Printf("Failed to authenticate this container: %s", err)
		os.Exit(2)
	}
}

func argError(error string) {
	if error != "" {
		fmt.Println("ERROR: " + error)
		fmt.Println(" ")
	}

	fmt.Println("usage: symbios <client/ca/container> <command> [<args>]")
	fmt.Println("Symbios runs at:")
	fmt.Println("   * client - where you run your docker client")
	fmt.Println("   * ca - in the certificate authority container")
	fmt.Println("   * container - in all other containers")
	fmt.Println(" ")
	fmt.Println("symbios client new-user")
	fmt.Println(" ")
	fmt.Println("symbios client new-token")
	fmt.Println(" ")
	fmt.Println("symbios client ca-hash")
	fmt.Println(" ")
	fmt.Println(" ")
	fmt.Println("symbios ca")
	fmt.Println(" ")
	fmt.Println(" ")
	fmt.Println("symbios container")
}
