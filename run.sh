#!/bin/bash

cargo b --release

if [[ $? -ne 0 ]]; then
    exit $?
fi;

home=/home/pragyan

sudo setcap cap_net_admin=eip $home/Rust/tcp_impl/target/release/tcp_impl
$home/Rust/tcp_impl/target/release/tcp_impl &

pid=$!


sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

trap "kill $pid" INT TERM
wait $pid
