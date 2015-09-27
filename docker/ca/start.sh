#!/bin/bash

#SYM_USER_KEY user defined
export SYM_PORT=3304
export SYM_KEY_SIZE=4098
export SYM_ORG=org
export SYM_COUNTRY=PT-PT
export SYM_DAYS=3650

symbios ca -port $SYM_PORT -user-key $SYM_USER_KEY -key-size $SYM_KEY_SIZE -organization $SYM_ORG -country $SYM_COUNTRY -days $SYM_DAYS &