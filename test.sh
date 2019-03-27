#!/bin/sh

#rm -rf accounts

test -d accounts || ~/work/thulin.net/multiverse/fe1.thulin.net/overlay/usr/sbin/dehydrated --config dehydrated_config.example --register --accept-terms

#PATH="$PATH:/home/ft/work/thulin.net/multiverse/fe1.thulin.net/overlay/usr/sbin/"
PATH="$PATH:./tmp"
dehydrated --config dehydrated_config.example --cron --domain test.test -t x-sunet-01
