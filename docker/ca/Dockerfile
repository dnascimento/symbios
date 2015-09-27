FROM golang
RUN go get -u github.com/dnascimento/symbios/src/symbios
RUN go get github.com/dgrijalva/jwt-go
RUN go install github.com/dnascimento/symbios/src/symbios

CMD symbios

