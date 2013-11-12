#!/bin/bash

iptables -t mangle -F
rmmod xt_ENCRYPT &>/dev/null
rmmod xt_COMPRESS &>/dev/null
iptables -t mangle -A OUTPUT -p udp -j COMPRESS --compress-algorithm deflate
iptables -t mangle -A OUTPUT -p udp -j ENCRYPT --encrypt-algorithm "cbc(aes)" --encrypt-passphrase 1234 --encrypt-perturb-time 10 --encrypt-perturb-number 10
iptables -t mangle -A OUTPUT -p udp -j ENCRYPT --encrypt-algorithm "cbc(aes)" --encrypt-passphrase 1234 --encrypt-decrypt
iptables -t mangle -A OUTPUT -p udp -j COMPRESS --compress-algorithm deflate --compress-decompress
