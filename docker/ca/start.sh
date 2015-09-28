#!/bin/bash

: ${SYM_PORT:=33004}
: ${SYM_KEY_SIZE:=4098}
: ${SYM_ORGANIZATION:=symbios}
: ${SYM_COUNTRY:=US}
: ${SYM_DAYS:=3650}

symbios ca -port $SYM_PORT -user-key $SYM_USER_KEY -key-size $SYM_KEY_SIZE -organization $SYM_ORG -country $SYM_COUNTRY -days $SYM_DAYS &
exec "$@"