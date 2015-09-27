# Symbios 
Symbios is an X.509 identity provisioning service designed to simplify mutual TLS authentication for microservices deployed in containers. This project helps you provision your PKI as easily as you provision containers and exposes an API for integration with your existing scheduling / deployment infrastructure.

Symbios accomplishes this without distribution or centralized management of secrets!

Symbios is result from a fork of [Pollendina](https://github.com/allingeek/pollendina), #2 at DockerCon Hackathon 2015


## Usage
### Setup (Create a CA container)
Install symbios in your localhost: 
```
go get github.com/dnascimento/symbios
go install github.com/dnascimento/symbios
```

Create user keys: 

`symbios client new-user`

Launch CA container injecting the obtained key and expose the port:

`docker run -i -t --name ca -e "SYM_USER_KEY=XXXXXXXXXXX"`

Get CA hash key
```
docker run -i -t --link ca:ca
symbios client ca-hash --host ca
```

You can close the latest container. Save this hash in your file system. It authenticates the certificate authority that you lunched.

### Add new container
Generate token
```
symbios client new-token -key id_rsa 
```

Launch new container
```
docker run -i -t -link ca:ca -e "SYM_TOKEN=XXXXXXXX" -e "SYM_CA_HASH=XXXXXXXX" -e "SYM_CA_HOST=ca"
```