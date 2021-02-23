#!/bin/bash
url='https://cdn.jsdelivr.net/gh/FenghenHome/filters@gh-pages/dnsmasq.accelerated-domains.conf'
data=$(curl -4sSkL "$url") || { echo "download failed, exit-code: $?"; exit 1; }
echo "$data" | awk -F/ '{print $2}' | sort | uniq >chnlist.txt
