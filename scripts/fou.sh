#!/bin/bash

set -x

ip netns add gw
ip netns add ext

ip netns add ns1

ip link add to-gw type veth peer eth0 netns gw
ip netns exec gw ip addr add 10.1.0.1/24 dev eth0
ip addr add 10.1.0.1/24 dev to-gw
ip link set up dev to-gw
ip netns exec gw ip link set up dev eth0

ip link add to-ext type veth peer eth0 netns ext
ip netns exec ext ip addr add 10.1.0.2/24 dev eth0
ip addr add 10.1.0.2/24 dev to-ext
ip link set up dev to-ext
ip netns exec ext ip link set up dev eth0

ip link add to-ns1 type veth peer eth0 netns ns1
ip netns exec ns1 ip addr add 10.0.0.2/24 dev eth0
ip addr add 10.0.0.2/24 dev to-ns1
ip link set up dev to-ns1
ip netns exec ns1 ip link set up dev eth0

ip netns exec ns1 ping -c 1 10.1.0.1
