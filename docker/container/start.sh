#!/bin/bash

export SYM_CA_HOST=localhost
export SYM_PORT=3304
export SYM_KEYOUT=/etc/secret/key
export SYM_CERTOUT=/etc/secret/client-cert.pem
export SYM_CA_CERT_OUT=/etc/secret/ca-cert.pem
export SYM_SIZE=2048

#SYM_TOKEN user defined
#SYM_CA_HASH user defined

export SYM_CN=Tommy
export SYM_IP_LIST=192.168.1.1
export SYM_DOMAIN_LIST=symbios
export SYM_ORGANIZATION=symbios
export SYM_COUNTRY=US

symbios container -host $SYM_CA_HOST -port $SYM_PORT -token $SYM_TOKEN -ca-hash $SYM_CA_HASH -keyout $SYM_KEYOUT -certout $SYM_CERTOUT -ca-cert-out $SYM_CA_CERT_OUT -size $SYM_SIZE -cn $SYM_CN -ip_list $SYM_IP_LIST -domain_list $SYM_DOMAIN_LIST -organization $SYM_ORGANIZATION -country $SYM_COUNTRY