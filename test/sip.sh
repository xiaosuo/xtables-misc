#!/bin/bash

iptables -t mangle -F
rmmod xt_sip &>/dev/null
iptables -t mangle -A OUTPUT -m sip -j ACCEPT
