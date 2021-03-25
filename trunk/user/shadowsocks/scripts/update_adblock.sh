#!/bin/sh

set -e -o pipefail
[ "$1" != "force" ] && [ "$(nvram get ss_update_adblock)" != "1" ] && exit 0
logger -st "adblock" "Starting update..."
curl -k -s -o /tmp/adblock_list.conf --connect-timeout 15 --retry 5 $(nvram get ss_adblock_url)
count=`awk '{print NR}' /tmp/adblock_list.conf|tail -n1`
if [ $count -gt 1000 ]; then
rm -f /etc/storage/dnsmasq.adblock/adblock_list.conf
cp -r /tmp/adblock_list.conf /etc/storage/dnsmasq.adblock/adblock_list.conf
mtd_storage.sh save >/dev/null 2>&1
mkdir -p /etc/storage/dnsmasq.adblock/
logger -st "adblock" "Update done"
if [ $(nvram get ss_enable) = 1 ]; then
logger -st "SS" "重启ShadowSocksR Plus+..."
/usr/bin/shadowsocks.sh stop
/usr/bin/shadowsocks.sh start
fi
if [ $(nvram get sdns_enable) = 1 ]; then
logger -st "SS" "重启smartdns..."
/usr/bin/smartdns.sh stop
/usr/bin/smartdns.sh start
fi
else
logger -st "adblock" "列表下载失败,请重试！"
fi
rm -f /tmp/adblock_list.conf
