#!/bin/sh
server_address=`lua /etc_ro/ss/getconfig.lua $1`
server_port=`lua /etc_ro/ss/getportconfig.lua $1`
ping_text=`tcping -q -c 1 -i 1 -t 2 -p $server_port $server_address`
ping_time=`echo $ping_text | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}'`
if [ -z "$ping_time" ]; then
	ping_time="failed"
else
ping_time=$(echo $ping_time | sed "s/\..*//g")
fi
lua /etc_ro/ss/ssping.lua $ping_time $1
