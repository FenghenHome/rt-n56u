#!/bin/sh
#
# Copyright (C) 2017 openwrt-ssr
# Copyright (C) 2017 yushi studio <ywb94@qq.com>
# Copyright (C) 2018 lean <coolsnowwolf@gmail.com>
# Copyright (C) 2020 Mattraks <mattraks@gmail.com>
# Copyright (C) 2019 chongshengB <bkye@vip.qq.com>
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#
NAME=shadowsocksr
LOCK_FILE=/var/lock/ssrplus.lock
LOG_FILE=/tmp/ssrplus.log
TMP_PATH=/tmp/ssrplus
TMP_BIN_PATH=$TMP_PATH/bin
ARG_OTA=
trojan_local_enable=`nvram get trojan_local_enable`
trojan_link=`nvram get trojan_link`
trojan_local=`nvram get trojan_local`
v2_local_enable=`nvram get v2_local_enable`
v2_link=`nvram get v2_link`
v2_local=`nvram get v2_local`
http_username=`nvram get http_username`
CONFIG_FILE=/tmp/${NAME}.json
CONFIG_UDP_FILE=/tmp/${NAME}_u.json
CONFIG_SOCK5_FILE=/tmp/${NAME}_s.json
CONFIG_KUMASOCKS_FILE=/tmp/kumasocks.toml
v2_json_file="/tmp/v2-redir.json"
trojan_json_file="/tmp/tj-redir.json"
server_count=0
redir_tcp=0
v2ray_enable=0
trojan_enable=0
redir_udp=0
tunnel_enable=0
local_enable=0
pdnsd_enable_flag=0
wan_bp_ips="/tmp/whiteip.txt"
wan_fw_ips="/tmp/blackip.txt"
lan_fp_ips="/tmp/lan_ip.txt"
run_mode=`nvram get ss_run_mode`
ss_turn=`nvram get ss_turn`
lan_con=`nvram get lan_con`
GLOBAL_SERVER=`nvram get global_server`
socks=""

clean_log() {
	local logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	[ "$logsnum" -gt 1000 ] && {
		echo "$(date "+%Y-%m-%d %H:%M:%S") 日志文件过长，清空处理！" >$LOG_FILE
	}
}

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$LOG_FILE
}

set_lock() {
	exec 1000>"$LOCK_FILE"
	flock -xn 1000
}

unset_lock() {
	flock -u 1000
	rm -rf "$LOCK_FILE"
}

unlock() {
	failcount=1
	while [ "$failcount" -le 10 ]; do
		if [ -f "$LOCK_FILE" ]; then
			let "failcount++"
			sleep 1s
			[ "$failcount" -ge 10 ] && unset_lock
		else
			break
		fi
	done
}

_exit() {
	local rc=$1
	unset_lock
	exit ${rc}
}

first_type() {
	type -t -p "/bin/${1}" -p "/tmp/${1}" -p "${TMP_BIN_PATH}/${1}" -p "${1}" "$@" | head -n1
}

ln_start_bin() {
	local file_func=${1}
	local ln_name=${2}
	shift 2
	if [ "${file_func%%/*}" != "${file_func}" ]; then
		[ ! -L "${file_func}" ] && {
			ln -s "${file_func}" "${TMP_BIN_PATH}/${ln_name}" >/dev/null 2>&1
			file_func="${TMP_BIN_PATH}/${ln_name}"
		}
		[ -x "${file_func}" ] || echolog "$(readlink ${file_func}) 没有执行权限，无法启动：${file_func} $*"
	fi
	[ -x "${file_func}" ] || {
		echolog "找不到 ${file_func}，无法启动..."
		echolog "-----------end------------"
		_exit 2
	}
	${file_func:-echolog "  - ${ln_name}"} "$@" >/dev/null 2>&1 &
}

start_dns() {
	local ss_dns=`nvram get ss_dns`
	local sdns_enable=`nvram get sdns_enable`
	local china_dns=`nvram get china_dns`
	local china_dns_server=$(echo "$china_dns" | awk -F '#' '{print $1}')
	local china_dns_port=$(echo "$china_dns" | awk -F '#' '{print $2}')
	start_pdnsd() {
		if [ ! -f "$TMP_PATH/pdnsd/pdnsd.cache" ]; then
			mkdir -p $TMP_PATH/pdnsd
			touch $TMP_PATH/pdnsd/pdnsd.cache
			chown -R nobody:nogroup $TMP_PATH/pdnsd
		fi
		cat <<-EOF >$TMP_PATH/pdnsd.conf
			global{
			perm_cache=1024;
			cache_dir="$TMP_PATH/pdnsd";
			pid_file="/var/run/pdnsd.pid";
			run_as="nobody";
			server_ip=0.0.0.0;
			server_port=65353;
			status_ctl=on;
			paranoid=on;
			query_method=udp_only;
			neg_domain_pol=off;
			par_queries = 400;
			min_ttl = 1h;
			max_ttl = 1w;
			timeout = 10;
			}
			server{
			label="routine";
			ip=$china_dns_server;
			port =$china_dns_port;
			timeout=5;
			reject = 74.125.127.102,
			74.125.155.102,  
			74.125.39.102,  
			74.125.39.113,  
			209.85.229.138,  
			128.121.126.139,  
			159.106.121.75,  
			169.132.13.103,  
			192.67.198.6,  
			202.106.1.2,  
			202.181.7.85,  
			203.161.230.171,  
			203.98.7.65,  
			207.12.88.98,  
			208.56.31.43,  
			209.145.54.50,  
			209.220.30.174,  
			209.36.73.33,  
			211.94.66.147,  
			213.169.251.35,  
			216.221.188.182,  
			216.234.179.13,  
			243.185.187.39,  
			37.61.54.158,  
			4.36.66.178,  
			46.82.174.68,  
			59.24.3.173,  
			64.33.88.161,  
			64.33.99.47,  
			64.66.163.251,  
			65.104.202.252,  
			65.160.219.113,  
			66.45.252.237,  
			69.55.52.253,  
			72.14.205.104,  
			72.14.205.99,  
			78.16.49.15,  
			8.7.198.45,  
			93.46.8.89,  
			37.61.54.158,  
			243.185.187.39,  
			190.93.247.4,  
			190.93.246.4,  
			190.93.245.4,  
			190.93.244.4,  
			65.49.2.178,  
			189.163.17.5,  
			23.89.5.60,  
			49.2.123.56,  
			54.76.135.1,  
			77.4.7.92,  
			118.5.49.6,  
			159.24.3.173,  
			188.5.4.96,  
			197.4.4.12,  
			220.250.64.24,  
			243.185.187.30,  
			249.129.46.48,  
			253.157.14.165;  
			reject_policy = fail;  
			}
			server {
			label = "special";
			ip = 208.67.222.222,208.67.220.220;
			port = 5353;
			proxy_only = on;
			timeout = 5;
			}
			source {
			owner=localhost;
			file="/etc/hosts";
			}
			rr {
			name=localhost;
			reverse=on;
			a=127.0.0.1;
			owner=localhost;
			soa=localhost,root.localhost,42,86400,900,86400,86400;
			}
		EOF
		chmod -R 744 $TMP_PATH/pdnsd.conf
		ln_start_bin $(first_type pdnsd) pdnsd -c $TMP_PATH/pdnsd.conf
	}
	if [ $ss_dns -gt 0 ] && [ $sdns_enable -eq 0 ]; then
		start_pdnsd
		pdnsd_enable_flag=1
		sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
		sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#65353
EOF
	fi
}

get_name() {
	case "$1" in
	ss) echo "Shadowsocks" ;;
	ssr) echo "ShadowsocksR" ;;
	esac
}

gen_config_file() {
	fastopen="false"
	case "$3" in
	0) config_file=$CONFIG_FILE ;;
	1) config_file=$CONFIG_UDP_FILE ;;
	*) config_file=$CONFIG_SOCK5_FILE ;;
	esac
	case "$2" in
	ss)
		lua /etc_ro/ss/genssconfig.lua $1 $4 >$config_file
		sed -i 's/\\//g' $config_file
		;;
	ssr)
		lua /etc_ro/ss/genssrconfig.lua $1 $4 >$config_file
		sed -i 's/\\//g' $config_file
		;;
	v2ray)
		v2_bin="/usr/bin/xray"
		if [ ! -f "$v2_bin" ]; then
		if [ ! -f "/tmp/xray" ];then
			if [ $v2_local_enable == "1" ] && [ -s $v2_local ] ; then
            logger -t "SS" "v2ray二进制文件复制成功"
            cat $v2_local > /tmp/xray
            chmod -R 777 /tmp/xray
            v2_bin="/tmp/xray"
else
    curl -k -s -o /tmp/xray --connect-timeout 10 --retry 3 $v2_link
    if [ -s "/tmp/xray" ] && [ `grep -c "404 Not Found" /tmp/xray` == '0' ] ; then
        logger -t "SS" "v2ray二进制文件下载成功"
        chmod -R 777 /tmp/xray
        v2_bin="/tmp/xray"
    else
        logger -t "SS" "v2ray二进制文件下载失败，可能是地址失效或者网络异常！"
        rm -f /tmp/xray
        nvram set ss_enable=0
        stop
    fi
fi
			else
			v2_bin="/tmp/xray"
			fi
		fi
		v2ray_enable=1
		if [ "$3" = "1" ]; then
			lua /etc_ro/ss/genv2config.lua $1 $mode 1080 >/tmp/v2-ssr-reudp.json
		sed -i 's/\\//g' /tmp/v2-ssr-reudp.json
		else
		lua /etc_ro/ss/genv2config.lua $1 $mode 1080 >$v2_json_file
		sed -i 's/\\//g' $v2_json_file
		fi
		;;
	trojan)
		tj_bin="/usr/bin/trojan"
		if [ ! -f "$tj_bin" ]; then
		if [ ! -f "/tmp/trojan" ];then
			if [ $trojan_local_enable == "1" ] && [ -s $trojan_local ] ; then
               logger -t "SS" "trojan二进制文件复制成功"
               cat $trojan_local > /tmp/trojan
               chmod -R 777 /tmp/trojan
               tj_bin="/tmp/trojan"
            else
               curl -k -s -o /tmp/trojan --connect-timeout 10 --retry 3 $trojan_link
                 if [ -s "/tmp/trojan" ] && [ `grep -c "404 Not Found" /tmp/trojan` == '0' ] ; then
                    logger -t "SS" "trojan二进制文件下载成功"
                    chmod -R 777 /tmp/trojan
                    tj_bin="/tmp/trojan"
                else
                    logger -t "SS" "trojan二进制文件下载失败，可能是地址失效或者网络异常！"
                    rm -f /tmp/trojan
                    nvram set ss_enable=0
                    stop
                fi
            fi
		else
			tj_bin="/tmp/trojan"
			fi
		fi
		trojan_enable=1
		if [ "$3" = "0" ]; then
		lua /etc_ro/ss/gentrojanconfig.lua $1 nat 1080 >$trojan_json_file
		sed -i 's/\\//g' $trojan_json_file
		else
		lua /etc_ro/ss/gentrojanconfig.lua $1 client 10801 >/tmp/trojan-ssr-reudp.json
		sed -i 's/\\//g' /tmp/trojan-ssr-reudp.json
		fi
		;;
	esac
}

start_udp() {
		local type=$(nvram get ud_type)
		redir_udp=1
		case "$type" in
		ss | ssr)
			gen_config_file $UDP_RELAY_SERVER $type 1 1080
			last_config_file=$CONFIG_UDP_FILE
			pid_file="/var/run/ssr-reudp.pid"
			ss_program="$(first_type ${type}local ${type}-redir)"
			[ "$(printf '%s' "$ss_program" | awk -F '/' '{print $NF}')" = "${type}local" ] &&
				local ss_extra_arg="--protocol redir -u" || local ss_extra_arg="-U"
			ln_start_bin $ss_program ${type}-redir -c $last_config_file $ss_extra_arg -f /var/run/ssr-reudp.pid >/dev/null 2>&1
			;;
		v2ray)
			gen_config_file $UDP_RELAY_SERVER $type 1
			ln_start_bin $(first_type xray v2ray) v2ray -config /tmp/v2-ssr-reudp.json
			echolog "UDP TPROXY Relay:$($(first_type "xray" "v2ray") -version | head -1) Started!"
			;;
		trojan) #client
			gen_config_file $UDP_RELAY_SERVER $type 1
			ln_start_bin $(first_type trojan) $type --config /tmp/trojan-ssr-reudp.json
			ln_start_bin $(first_type ipt2socks) ipt2socks -U -b 0.0.0.0 -4 -s 127.0.0.1 -p 10801 -l 1080
			echolog "UDP TPROXY Relay:$($(first_type trojan) --version 2>&1 | head -1) Started!"
			;;
		socks5)
		echo "1"
		    ;;
		esac
}

# ================================= 启动 Socks5代理 ===============================
start_local() {
	local local_port=$(nvram get socks5_port)
	local type=$(nvram get s5_type)
	case "$type" in
	ss | ssr)
		gen_config_file $LOCAL_SERVER $type 3 $local_port
		ss_program="$(first_type ${type}local ${type}-local)"
		[ "$(printf '%s' "$ss_program" | awk -F '/' '{print $NF}')" = "${type}local" ] &&
			local ss_extra_arg="-U" || local ss_extra_arg="-u"
		ln_start_bin $ss_program ${type}-local -c $CONFIG_SOCK5_FILE $ss_extra_arg -f /var/run/ssr-local.pid >/dev/null 2>&1
		echolog "Global_Socks5:$(get_name $type) Started!"
		;;
	v2ray)
		lua /etc_ro/ss/genv2config.lua $LOCAL_SERVER $mode 0 $local_port >/tmp/v2-ssr-local.json
		sed -i 's/\\//g' /tmp/v2-ssr-local.json
		ln_start_bin $(first_type xray v2ray) v2ray -config /tmp/v2-ssr-local.json
		echolog "Global_Socks5:$($(first_type "xray" "v2ray") -version | head -1) Started!"
		;;
	trojan)
		lua /etc_ro/ss/gentrojanconfig.lua $LOCAL_SERVER client $local_port >/tmp/trojan-ssr-local.json
		sed -i 's/\\//g' /tmp/trojan-ssr-local.json
		ln_start_bin $(first_type trojan) $type --config /tmp/trojan-ssr-local.json
		echolog "Global_Socks5:$($(first_type trojan) --version 2>&1 | head -1) Started!"
		;;
	*)
		[ -e /proc/sys/net/ipv6 ] && local listenip='-i ::'
		ln_start_bin $(first_type microsocks) microsocks $listenip -p $local_port tcp-udp-ssr-local
		echolog "Global_Socks5:$type Started!"
		;;
	esac
	local_enable=1
	return 0
}

Start_Run() {
	if [ "$(nvram get ss_threads)" == "0" ]; then
		local threads=$(cat /proc/cpuinfo | grep 'processor' | wc -l)
	else
		local threads=$(nvram get ss_threads)
	fi
	local type=$(nvram get d_type)
	gen_config_file $GLOBAL_SERVER $type 0 1080
	case "$type" in
	ss | ssr)
		last_config_file=$CONFIG_FILE
		ss_program="$(first_type ${type}local ${type}-redir)"
		[ "$(printf '%s' "$ss_program" | awk -F '/' '{print $NF}')" = "${type}local" ] &&
			{
				local ss_extra_arg="--protocol redir"
				case ${ARG_OTA} in '-u') ARG_OTA='-U' ;; esac
			}
		for i in $(seq 1 $threads); do
			ln_start_bin "$ss_program" ${type}-redir -c $CONFIG_FILE $ARG_OTA $ss_extra_arg -f /tmp/ssr-retcp_$i.pid >/dev/null 2>&1
			usleep 500000
		done
		redir_tcp=1
		echolog "Main node:$(get_name $type) $threads Threads Started!"
		;;
	v2ray)
		ln_start_bin $(first_type xray v2ray) v2ray -config $v2_json_file
		echolog "Main node:$($(first_type xray v2ray) -version | head -1) Started!"
		;;
	trojan)
		for i in $(seq 1 $threads); do
			ln_start_bin $(first_type $type) $type --config $trojan_json_file
			usleep 500000
		done
		echolog "Main node:$($(first_type $type) --version 2>&1 | head -1) , $threads Threads Started!"
		;;
	socks5)
		for i in $(seq 1 $threads); do
		lua /etc_ro/ss/gensocks.lua $GLOBAL_SERVER 1080 >/dev/null 2>&1 &
		usleep 500000
		done
		;;
	esac
	return 0
}

load_config() {
	if [ "$GLOBAL_SERVER" == "nil" ]; then
		return 1
	fi
	UDP_RELAY_SERVER=$(nvram get udp_relay_server)
	LOCAL_SERVER=$(nvram get socks5_enable)
	case "$UDP_RELAY_SERVER" in
	nil)
		mode="tcp"
		;;
	$GLOBAL_SERVER | same)
		mode="tcp,udp"
		ARG_UDP="-u"
		UDP_RELAY_SERVER=$GLOBAL_SERVER
		;;
	*)
		mode="udp"
		ARG_UDP="-U"
		start_udp
		mode="tcp"
		;;
	esac
	case "$LOCAL_SERVER" in
	nil)
		_local="0"
		;;
	$GLOBAL_SERVER | same)
		_local="1"
		LOCAL_SERVER=$GLOBAL_SERVER
		start_local
		local_enable=0
		;;
	*)
		_local="2"
		start_local
		;;
	esac
	return 0
}

start_monitor() {
	if [ $(nvram get ss_watchcat) == "1" ]; then
		let total_count=server_count+redir_tcp+redir_udp+tunnel_enable+v2ray_enable+local_enable+pdnsd_enable_flag+trojan_enable
		if [ $total_count -gt 0 ]; then
			/usr/bin/ssr-monitor $server_count $redir_tcp $redir_udp $tunnel_enable $v2ray_enable $local_enable $pdnsd_enable_flag $trojan_enable >/dev/null 2>&1 &
		fi
	fi
}

start_rules() {
    logger -t "SS" "正在添加防火墙规则..."
	lua /etc_ro/ss/getconfig.lua $GLOBAL_SERVER > /tmp/server.txt
	server=`cat /tmp/server.txt` 
	cat /etc/storage/ss_ip.sh | grep -v '^!' | grep -v "^$" >$wan_fw_ips
	cat /etc/storage/ss_wan_ip.sh | grep -v '^!' | grep -v "^$" >$wan_bp_ips
	#resolve name
	if echo $server | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >/dev/null; then
		server=${server}
	elif [ "$server" != "${server#*:[0-9a-fA-F]}" ]; then
		server=${server}
	else
		server=$(ping ${server} -s 1 -c 1 | grep PING | cut -d'(' -f 2 | cut -d')' -f1)
		if echo $server | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >/dev/null; then
			echo $server >/etc/storage/ssr_ip
		else
			server=$(cat /etc/storage/ssr_ip)
		fi
	fi
	local_port="1080"
	if [ "$redir_udp" == "1" ]; then
		ARG_UDP="-U"
		lua /etc_ro/ss/getconfig.lua $UDP_RELAY_SERVER > /tmp/userver.txt
		udp_server=`cat /tmp/userver.txt` 
		udp_local_port="1080"
	fi
	gfwmode() {
		case "$run_mode" in
		gfw) echo "-g" ;;
		router) echo "-r" ;;
		oversea) echo "-c" ;;
		all) echo "-z" ;;
		esac
	}
	if [ "$lan_con" = "0" ]; then
		rm -f $lan_fp_ips
		lancon="all"
		lancons="全部IP走代理"
		cat /etc/storage/ss_lan_ip.sh | grep -v '^!' | grep -v "^$" >$lan_fp_ips
	elif [ "$lan_con" = "1" ]; then
		rm -f $lan_fp_ips
		lancon="bip"
		lancons="指定IP走代理,请到规则管理页面添加需要走代理的IP。"
		cat /etc/storage/ss_lan_bip.sh | grep -v '^!' | grep -v "^$" >$lan_fp_ips
	fi
	if [ "$(nvram get s_dports)" == "1" ]; then
		local proxyport="-m multiport --dports 22,53,587,465,995,993,143,80,443,853,9418"
	fi
	get_arg_out() {
		router_proxy="1"
		case "$router_proxy" in
		1) echo "-o" ;;
		2) echo "-O" ;;
		esac
	}
	/usr/bin/ssr-rules \
		-s "$server" \
		-l "$local_port" \
		-S "$udp_server" \
		-L "$udp_local_port" \
		-a "$ac_ips" \
		-i "/etc/storage/chinadns/chnroute.txt" \
		-b "$wan_bp_ips" \
		-w "$wan_fw_ips" \
		-p "$lan_fp_ips" \
		-G "$lan_gm_ips" \
		-D "$proxyport" \
		-k "$lancon" \
		$(get_arg_out) $(gfwmode) $ARG_UDP
	return $?
}

start() {
	set_lock
	echolog "----------start------------"
	mkdir -p /var/run /var/lock /var/log $TMP_BIN_PATH
	ulimit -n 65535
	ss_enable=`nvram get ss_enable`
	if load_config; then
		Start_Run
		start_rules
		start_dns
	fi
	start_monitor
        auto_update
        ENABLE_SERVER=$(nvram get global_server)
        [ "$ENABLE_SERVER" = "-1" ] && return 1

        logger -t "SS" "启动成功。"
        logger -t "SS" "内网IP控制为:$lancons"
	clean_log
	/sbin/restart_dhcpd >/dev/null 2>&1
	echolog "-----------end------------"
	unset_lock
}

stop() {
	unlock
	set_lock
	/usr/bin/ssr-rules -f
	ps -w | grep -v "grep" | grep ssr-monitor | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1 &
	ps -w | grep -v "grep" | grep "sleep 0000" | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1 &
	ps -w | grep -v "grep" | grep "$TMP_PATH" | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1 &
	kill_process
	rm -f /var/lock/ssr-monitor.lock
	sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
	clear_iptable
	/sbin/restart_dhcpd >/dev/null 2>&1
	unset_lock
}

clear_iptable()
{
	s5_port=$(nvram get socks5_port)
	iptables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	iptables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	ip6tables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	ip6tables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	
}

auto_update() {
	sed -i '/update_chnroute/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/update_gfwlist/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/update_adblock/d' /etc/storage/cron/crontabs/$http_username
	if [ $(nvram get ss_update_chnroute) = "1" ]; then
		cat >>/etc/storage/cron/crontabs/$http_username <<EOF
40 1 * * * /usr/bin/update_chnroute.sh > /dev/null 2>&1
EOF
	fi
	if [ $(nvram get ss_update_gfwlist) = "1" ]; then
		cat >>/etc/storage/cron/crontabs/$http_username <<EOF
45 1 * * * /usr/bin/update_gfwlist.sh > /dev/null 2>&1
EOF
	fi
	if [ $(nvram get ss_update_adblock) = "1" ]; then
		cat >>/etc/storage/cron/crontabs/$http_username <<EOF
50 1 * * * /usr/bin/update_adblock.sh > /dev/null 2>&1
EOF
	fi
}

find_bin() {
	case "$1" in
	ss) ret="/usr/bin/ss-redir" ;;
	ss-local) ret="/usr/bin/ss-local" ;;
	ssr) ret="/usr/bin/ssr-redir" ;;
	ssr-local) ret="/usr/bin/ssr-local" ;;
	ssr-server) ret="/usr/bin/ssr-server" ;;
	v2ray)
	if [ -f "/usr/bin/xray" ] ; then
       ret="/usr/bin/xray"
    else
       ret="/tmp/xray"
    fi
    ;;
	trojan)
	if [ -f "/usr/bin/trojan" ] ; then
       ret="/usr/bin/trojan"
    else
       ret="/tmp/trojan"
    fi
    ;;
	socks5) ret="/usr/bin/ipt2socks" ;;
	esac
	echo $ret
}

kill_process() {
	v2ray_process=$(pidof xray)
	if [ -n "$v2ray_process" ]; then
		logger -t "SS" "关闭V2Ray进程..."
		killall -q -9 xray >/dev/null 2>&1
		kill -9 "$v2ray_process" >/dev/null 2>&1
	fi
	ssredir=$(pidof ss-redir)
	if [ -n "$ssredir" ]; then
		logger -t "SS" "关闭ss-redir进程..."
		killall -q -9 ss-redir >/dev/null 2>&1
		kill -9 "$ssredir" >/dev/null 2>&1
	fi

	rssredir=$(pidof ssr-redir)
	if [ -n "$rssredir" ]; then
		logger -t "SS" "关闭ssr-redir进程..."
		killall -q -9 ssr-redir >/dev/null 2>&1
		kill -9 "$rssredir" >/dev/null 2>&1
	fi
	
	sslocal_process=$(pidof ss-local)
	if [ -n "$sslocal_process" ]; then
		logger -t "SS" "关闭ss-local进程..."
		killall -q -9 ss-local >/dev/null 2>&1
		kill -9 "$sslocal_process" >/dev/null 2>&1
	fi

	trojandir=$(pidof trojan)
	if [ -n "$trojandir" ]; then
		logger -t "SS" "关闭trojan进程..."
		killall -q -9 trojan >/dev/null 2>&1
		kill -9 "$trojandir" >/dev/null 2>&1
	fi

	kumasocks_process=$(pidof kumasocks)
	if [ -n "$kumasocks_process" ]; then
		logger -t "SS" "关闭kumasocks进程..."
		killall -q -9 kumasocks >/dev/null 2>&1
		kill -9 "$kumasocks_process" >/dev/null 2>&1
	fi
	
	ipt2socks_process=$(pidof ipt2socks)
	if [ -n "$ipt2socks_process" ]; then
		logger -t "SS" "关闭ipt2socks进程..."
		killall -q -9 ipt2socks >/dev/null 2>&1
		kill -9 "$ipt2socks_process" >/dev/null 2>&1
	fi

	socks5_process=$(pidof srelay)
	if [ -n "$socks5_process" ]; then
		logger -t "SS" "关闭socks5进程..."
		killall -q -9 srelay >/dev/null 2>&1
		kill -9 "$socks5_process" >/dev/null 2>&1
	fi

	ssrs_process=$(pidof ssr-server)
	if [ -n "$ssrs_process" ]; then
		logger -t "SS" "关闭ssr-server进程..."
		killall -q -9 ssr-server >/dev/null 2>&1
		kill -9 "$ssrs_process" >/dev/null 2>&1
	fi
	
	cnd_process=$(pidof chinadns-ng)
	if [ -n "$cnd_process" ]; then
		logger -t "SS" "关闭chinadns-ng进程..."
		killall -q -9 chinadns-ng >/dev/null 2>&1
		kill -9 "$cnd_process" >/dev/null 2>&1
	fi

	pdnsd_process=$(pidof pdnsd)
	if [ -n "$pdnsd_process" ]; then
		logger -t "SS" "关闭pdnsd进程..."
		killall -q -9 pdnsd >/dev/null 2>&1
		kill -9 "$pdnsd_process" >/dev/null 2>&1
	fi

	microsocks_process=$(pidof microsocks)
	if [ -n "$microsocks_process" ]; then
		logger -t "SS" "关闭socks5服务端进程..."
		killall -q -9 microsocks >/dev/null 2>&1
		kill -9 "$microsocks_process" >/dev/null 2>&1
	fi

	v2ray-plugin_process=$(pidof v2ray-plugin)
	if [ -n "$v2ray-plugin_process" ]; then
		logger -t "SS" "关闭v2ray-plugin进程..."
		killall -q -9 v2ray-plugin >/dev/null 2>&1
		kill -9 "$v2ray-plugin_process" >/dev/null 2>&1
	fi

	obfs-local_process=$(pidof obfs-local)
	if [ -n "$obfs-local_process" ]; then
		logger -t "SS" "关闭obfs-local进程..."
		killall -q -9 obfs-local >/dev/null 2>&1
		kill -9 "$obfs-local_process" >/dev/null 2>&1
	fi
}


# ================================= 重启 SS ===============================
ressp() {
	BACKUP_SERVER=$(nvram get backup_server)
	start_redir $BACKUP_SERVER
	start_rules $BACKUP_SERVER
	start_local
	start_monitor
	auto_update
	ENABLE_SERVER=$(nvram get global_server)
	logger -t "SS" "备用服务器启动成功"
	logger -t "SS" "内网IP控制为:$lancons"
}

case $1 in
start)
	start
	;;
stop)
	stop
	;;
restart)
	stop
	start
	;;
reserver)
	stop
	ressp
	;;
*)
	echo "check"
	#exit 0
	;;
esac

