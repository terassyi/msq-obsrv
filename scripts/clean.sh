#!/bin/bash

set -x

ip netns del gw
ip netns del ext

for i in $(seq 1 $1)
do
        ip netns del ns$i
done
