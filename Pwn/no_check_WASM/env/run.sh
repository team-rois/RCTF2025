#!/bin/bash

JSFILE="/tmp/$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n').js"
touch $JSFILE
function cleanup {
    rm -f "$JSFILE"
}
trap cleanup EXIT
timeout 60 python3 -u /server.py $JSFILE
