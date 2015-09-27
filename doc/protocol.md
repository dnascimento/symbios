# Symbios 
Symbios is an X.509 identity provisioning service designed to simplify mutual TLS authentication for microservices deployed in containers. This project helps you provision your PKI as easily as you provision containers and exposes an API for integration with your existing scheduling / deployment infrastructure.

Symbios accomplishes this without distribution or centralized management of secrets!



### Setup
1. User generates a key pair (openssl or symbios-client new-user) and stores the key
2. User launches a CA container injecting user's public key
3. The CA container generates its root-certificate
4. User obtains the hash of CA root-certificate.

### Usage
1. User obtains a new JWT token by generating a random nonce and signing it with its private key. (symbios-client new-token id.rsa)
3. User launches a new container injecting the token and root-certificate hash.
4. The container downloads the CA root-certificate
6. The container verifies the root-certificate against the hash to authenticate the CA.
7. The container sends a certificate signing request (CSR) with the token
8. The CA validates the token with the user key.
9. The CA signs the key in CSR generating container's certificate.
10. The container validates the retrieved certificate
11. The certificate is stored.

