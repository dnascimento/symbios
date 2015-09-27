## Symbios - Tech Spec

### Commands
#### Client

- symbios new-user -out ./id.rsa --size 2048 --username dario
- symbios new-token id.rsa 
- symbios ca-hash 192.168.20.12


####  Certificate Authority

- symbios ca user_pub_key

#### Container Client

- symbios container authenticate --key id.rsa --out id.crt 192.168.120.10:12 <token var> 



### API
#### CA's REST API Spec:

* GET /hash                   	  - user authentication required
* GET /cert                       - public
* POST /csr                       - token required


#### Client Methods
- newUserKey(size, destPath, destName)
- newNonce(size) String
- newToken(nonce, privKey) string
- getCACertHash()

#### CA Methods
- newRootCertificate(size) KeyPair
- getCertHash() string
- getCert() Certificate
- validateToken(token, userKey) Boolean
- setUserKey(location)
- signCSR(csr) Certificate

#### Container Methods
- getCaCert(hostname) Certificate
- checkCertificateHash(certificate, hash) Boolean
- requestCertificate(hostname, token, key) Certificate
- checkCertificate(certificate, rootCertificate) Boolean









