#!/bin/bash
#nothing up my sleeve
docker rm -fv $(docker ps -aq) && docker ps

docker run -d --name ca symbios/ca bash -c "symbios new-user | tee user_key && export SYM_USER_KEY=\$(cat user_key) && /start.sh && while true; do echo alive; sleep 300; done"

IP=$(docker ps | grep ca | cut -d' ' -f1 | xargs -I {} docker inspect {} | grep \"IPA | cut -d'"' -f4)

for i in `seq 60`; do
  echo -n "Checking if the CA is responding:   "
  curl $IP:33004
  if [ $? = 0 ]; then
    break
  fi
  sleep 1
done

docker exec -t ca bash -c "symbios ca-hash --host 127.0.0.1 | tee ca_fingerprint" > fingerprint

docker exec -ti ca bash -c "symbios new-token -key id_rsa | tee latest_key" > latest_key

docker run -it -e "SYM_TOKEN=$(cat latest_key)" -e "SYM_CA_HASH=$(cat fingerprint)" -e "SYM_CA_HOST=$IP" symbios/container bash -c "cd /etc/secret/ && ls && bash"
