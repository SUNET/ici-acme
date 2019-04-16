#!/bin/sh

#rm -rf ./dehydrated_client/accounts

PATH="$PATH:./dehydrated_client"

test -d ./dehydrated_client/accounts || dehydrated --config ./dehydrated_client/dehydrated_config.example --register --accept-terms

./tools/ici-acme-pre-auth.py --dehydrated_account_dir ./dehydrated_client/accounts/* \
			     --cert dehydrated_client/certs/test.test/cert.pem \
			     --key dehydrated_client/certs/test.test/privkey.pem || exit 1

dehydrated -a prime256v1 --force --config ./dehydrated_client/dehydrated_config.example --cron -t x-sunet-01 #--domain test.test
