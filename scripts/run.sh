#!/bin/bash

set -x

KEEPALIVE=-k
if [ -z "$4" ]; then
        KEEPALIVE=""
fi


for i in $(seq 1 $1)
do
        ip netns exec ns$1 ab -n $2 -c $3 $KEEPALIVE http://10.1.0.2:80/  &
done
wait
