FROM golang
COPY . /go/src/github.com/dnascimento/symbios
RUN go install github.com/dnascimento/symbios/symbios-ca
RUN go install github.com/dnascimento/symbios/symbios-client

CMD symbios-client

