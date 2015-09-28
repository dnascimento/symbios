# Symbios 
Symbios is an X.509 identity provisioning service designed to simplify mutual TLS authentication for microservices deployed in containers. This project helps you provision your PKI as easily as you provision containers and exposes an API for integration with your existing scheduling / deployment infrastructure.

Symbios accomplishes this without distribution or centralized management of secrets!

Symbios is result from a fork of [Pollendina](https://github.com/allingeek/pollendina), #2 at DockerCon Hackathon 2015

Symbios comes from the symbiose relation between containers exchanging data with SSL/TLS.

### Protocol
[Protocol details](https://github.com/dnascimento/symbios/blob/master/PROTOCOL.md)

## Usage
### Setup (Create a CA container)
Install symbios in your localhost: 
```
go get github.com/dnascimento/symbios
go install github.com/dnascimento/symbios/src/symbios
```

Create user keys: 

`symbios new-user`

Launch CA container injecting the obtained key as environment variable:
```
docker run -i -t --name ca -e "SYM_USER_KEY=<key obtained previously>" symbios/ca bash
```

Get Certificate Authority root-certificate fingerprint
```
docker run -i -t --link ca:ca symbios/base symbios ca-hash --host ca | tee fingerprint
```

Keep the fingerprint file. It authenticates the certificate authority that you lunched.

### Add new container
Generate token
```
symbios new-token -key id_rsa 
```

Launch new container injecting the token
```
docker run -i -t -link ca:ca -e "SYM_TOKEN=<token obtained previously>" -e "SYM_CA_HASH=<fingerprint file content>" -e "SYM_CA_HOST=ca" symbios/container bash
```


## Contributors
- [Dário Nascimento](https://github.com/dnascimento)

## Kudos
- [CoreOS Pkix Project](https://github.com/coreos/etcd-ca/tree/master/pkix)
- Diogo Mónica
- Jeff Nickoloff - original idea

## Hackathon Pollendina Contributors 

- [Jeff Nickoloff](https://github.com/allingeek)
- [Dário Nascimento](https://github.com/dnascimento)
- [Jason Huddleston](https://github.com/huddlesj) [Docker newbie]
- [Madhuri Yechuri](https://github.com/myechuri)
- [Henry Kendall](https://github.com/hskendall) [Docker newbie]
