FROM golang
RUN go get github.com/dnascimento/symbios
RUN go get github.com/dgrijalva/jwt-go
RUN go install github.com/dnascimento/symbios/src/symbios

ENTRYPOINT start.sh

