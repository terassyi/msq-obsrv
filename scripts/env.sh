#!/bin/bash

set -x

ip netns add gw
ip netns add ext

ip netns exec gw ip link add to-ext type veth peer to-gw netns ext
ip netns exec gw ip addr add 10.1.0.1/24 dev to-ext
ip netns exec ext ip addr add 10.1.0.2/24 dev to-gw

ip netns exec gw ip link set up dev to-ext
ip netns exec ext ip link set up dev to-gw

ip netns exec gw ip route add default via 10.1.0.2 dev to-ext

ip netns exec gw ping -c 1 10.1.0.2

ip netns exec gw sysctl -w net.ipv4.ip_forward=1

ip netns exec gw iptables -t nat -A POSTROUTING -o to-ext -j MASQUERADE

for i in $(seq 1 $1)
do
        ip netns add ns$i
        ip netns exec ns$i ip link add to-gw type veth peer to-ns$i netns gw
        ip netns exec ns$i ip addr add 10.0.$i.1/24 dev to-gw
        ip netns exec gw ip addr add 10.0.$i.2/24 dev to-ns$i
        ip netns exec ns$i ip link set up dev to-gw
        ip netns exec gw ip link set up dev to-ns$i
        ip netns exec ns$i ip route add default via 10.0.$i.2 dev to-gw
done


for i in $(seq 1 $1)
do
        ip netns exec ns$i ping -c 1 -w 1 10.0.$i.2
        ip netns exec ns$i ping -c 1 -w 1 10.1.0.2
done
