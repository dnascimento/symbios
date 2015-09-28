#!/bin/bash

: ${SYM_CA_HOST:=localhost}
: ${SYM_PORT:=33004}
: ${SYM_KEYOUT:=/etc/secret/id.pem}
: ${SYM_CERTOUT:=/etc/secret/id_cert.pem}
: ${SYM_CA_CERT_OUT:=/etc/secret/ca_cert.pem}
: ${SYM_SIZE:=2048}

#SYM_TOKEN user defined
#SYM_CA_HASH user defined

: ${SYM_CN:=""}
: ${SYM_IP_LIST:=""}
: ${SYM_DOMAIN_LIST:=""}
: ${SYM_ORGANIZATION:=symbios}
: ${SYM_COUNTRY:=US}

symbios container -host $SYM_CA_HOST -port $SYM_PORT -token $SYM_TOKEN -ca-hash $SYM_CA_HASH -keyout $SYM_KEYOUT -certout $SYM_CERTOUT -ca-cert-out $SYM_CA_CERT_OUT -size $SYM_SIZE -cn $SYM_CN -ip_list $SYM_IP_LIST -domain_list $SYM_DOMAIN_LIST -organization $SYM_ORGANIZATION -country $SYM_COUNTRY
exec "$@"