#!/bin/sh

#rm -rf ./dehydrated_client/accounts

PATH="$PATH:./dehydrated_client"

test -d ./dehydrated_client/accounts || dehydrated --config ./dehydrated_client/dehydrated_config.example --register --accept-terms

dehydrated --config ./dehydrated_client/dehydrated_config.example --cron --domain test.test -t x-sunet-01
