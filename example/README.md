# Symbios HTTP Server/Client example

The example requires the [Go HTTP Server Client Mutual Auth](https://github.com/dnascimento/GoHttpsMutualAuth).

Install Docker
Create docker images of HTTP Mutual Auth server/client

```
git clone https://github.com/dnascimento/GoHttpsMutualAuth
sh build.sh
```

Follow the instructions in [README](https://github.com/dnascimento/symbios/blob/master/README.md) to setup symbios creating a Certificate Authority container.

Create a new token
```
symbios new-token 
```

Launch the HTTP server container (image: mutual/server, cmd: bash)
```
docker run -i -t --name server --link ca:ca -e "SYM_TOKEN=<token obtained previously>" -e "SYM_CA_HASH=<fingerprint file content>" -e "SYM_CA_HOST=ca" mutual/server bash
```

Create another token
```
symbios new-token 
```


Launch the HTTP client container (image: mutual/client, cmd: bash)
```
docker run -i -t --link ca:ca --link server:server -e "SYM_TOKEN=<token obtained previously>" -e "SYM_CA_HASH=<fingerprint file content>" -e "SYM_CA_HOST=ca" mutual/client bash
```


On server container:
```
http-server  9000 /etc/secret/id.pem /etc/secret/id_cert.pem /etc/secret/ca_cert.pem
```

On client container:
```
http-client  server:9000 /etc/secret/id.pem /etc/secret/id_cert.pem /etc/secret/ca_cert.pem 
```


This is it :) The difference between no authentication or strong mutual authentication is less than 10 lines in GoLang!