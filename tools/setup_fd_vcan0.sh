#!/bin/sh
sudo ip link add dev vcan1 type vcan
sudo ip link set vcan1 mtu 72
sudo ip link set up vcan1
