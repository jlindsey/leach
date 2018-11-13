#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

CONSUL_ADDR="${CONSUL_ADDR:-127.0.0.1:8500}"
CONSUL_PREFIX="${CONSUL_PREFIX:-leach}"
export EMAIL_ADDR="$(openssl rand -hex 10)@mailinator.com"

envsubst < $DIR/conf.json > $DIR/conf.json.out
curl --request PUT --data @$DIR/conf.json.out http://$CONSUL_ADDR/v1/kv/$CONSUL_PREFIX/config
rm -f $DIR/conf.json.out
echo $EMAIL_ADDR
unset EMAIL_ADDR
