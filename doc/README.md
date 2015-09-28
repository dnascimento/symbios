# Symbios 
Symbios is an X.509 identity provisioning service designed to simplify mutual TLS authentication for microservices deployed in containers. This project helps you provision your PKI as easily as you provision containers and exposes an API for integration with your existing scheduling / deployment infrastructure.

Symbios accomplishes this without distribution or centralized management of secrets!



### Setup
1. User generates a key pair (openssl or symbios-client new-user) and stores the key
2. User launches a CA container injecting user's public key
3. The CA container generates its root-certificate
4. User obtains the hash of CA root-certificate.

![Setup](https://raw.githubusercontent.com/dnascimento/symbios/master/doc/setup.png)

### Usage
1. User obtains a new JWT token by generating a random nonce and signing it with its private key. (symbios-client new-token id.rsa)
3. User launches a new container injecting the token and root-certificate hash.
4. The container downloads the CA root-certificate (no TLS validation required)
6. The container verifies the root-certificate against the hash to authenticate the CA.
7. The container sends a certificate signing request (CSR) with the token (TLS is used to avoid man-in-the-middle)
8. The CA validates the token with the user key.
9. The CA signs the key in CSR generating container's certificate.
10. The container validates the retrieved certificate
11. The certificate is stored.

![Authentication](https://github.com/dnascimento/symbios/blob/master/doc/authentication.png)
### Man in the middle Attack
* The root-certificate is downloaded without TLS validation because the container knows its fingerprint.
* The CSR is sent using server TLS authentication. The Certificate Authority generates and signs a certificate to use as HTTPS server. The root-certificate is used only for signing.
* While an attacker could stole the token to sign his key, the CSR and token are ciphered using the CA HTTPS cert.
* An alternative would involve to generate key and then generate the token with its fingerprint requiring the client to generate container's key or to send the fingerprint from the container to client or to inject the user key in every container.
