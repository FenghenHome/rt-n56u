#!/bin/sh
#
# Copyright (C) 2017 openwrt-ssr
# Copyright (C) 2017 yushi studio <ywb94@qq.com>
# Copyright (C) 2018 lean <coolsnowwolf@gmail.com>
# Copyright (C) 2019 chongshengB <bkye@vip.qq.com>
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#
NAME=shadowsocksr
LOCK_FILE=/tmp/ssrplus.lock
LOG_FILE=/tmp/ssrplus.log
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

gen_config_file() {
	fastopen="false"
	case "$2" in
	0) config_file=$CONFIG_FILE && local stype=$(nvram get d_type) ;;
	1) config_file=$CONFIG_UDP_FILE && local stype=$(nvram get ud_type) ;;
	*) config_file=$CONFIG_SOCK5_FILE && local stype=$(nvram get s5_type) ;;
	esac
local type=$stype
	case "$type" in
	ss)
		lua /etc_ro/ss/genssconfig.lua $1 $3 >$config_file
		sed -i 's/\\//g' $config_file
		;;
	ssr)
		lua /etc_ro/ss/genssrconfig.lua $1 $3 >$config_file
		sed -i 's/\\//g' $config_file
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
                    ssp_close
                fi
            fi
		else
			tj_bin="/tmp/trojan"
			fi
		fi
		trojan_enable=1
		#tj_file=$trojan_json_file
		if [ "$2" = "0" ]; then
		lua /etc_ro/ss/gentrojanconfig.lua $1 nat 1080 >$trojan_json_file
		sed -i 's/\\//g' $trojan_json_file
		else
		lua /etc_ro/ss/gentrojanconfig.lua $1 client 10801 >/tmp/trojan-ssr-reudp.json
		sed -i 's/\\//g' /tmp/trojan-ssr-reudp.json
		fi
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
        ssp_close
    fi
fi
			else
			v2_bin="/tmp/xray"
			fi
		fi
		v2ray_enable=1
		if [ "$2" = "1" ]; then
			if [ "$UDP_RELAY_SERVER" != "same" ] ; then
			lua /etc_ro/ss/genv2config.lua $1 udp 1080 >/tmp/v2-ssr-reudp.json
			else
			lua /etc_ro/ss/genv2config.lua $1 tcp,udp 1080 >/tmp/v2-ssr-reudp.json
			fi
		sed -i 's/\\//g' /tmp/v2-ssr-reudp.json
		else
		lua /etc_ro/ss/genv2config.lua $1 tcp 1080 >$v2_json_file
		sed -i 's/\\//g' $v2_json_file
		fi
		;;
	esac
}

start_redir_tcp() {
	ARG_OTA=""
	gen_config_file $GLOBAL_SERVER 0 1080
	stype=$(nvram get d_type)
	local bin=$(find_bin $stype)
	[ ! -f "$bin" ] && echo "$(date "+%Y-%m-%d %H:%M:%S") Main node:Can't find $bin program, can't start!" >>$LOG_FILE && return 1
	if [ "$(nvram get ss_threads)" = "0" ]; then
		threads=$(cat /proc/cpuinfo | grep 'processor' | wc -l)
	else
		threads=$(nvram get ss_threads)
	fi
	logger -t "SS" "启动$stype主服务器..."
	case "$stype" in
	ss | ssr)
		last_config_file=$CONFIG_FILE
		pid_file="/tmp/ssr-retcp.pid"
		for i in $(seq 1 $threads); do
			$bin -c $CONFIG_FILE $ARG_OTA -f /tmp/ssr-retcp_$i.pid >/dev/null 2>&1
			usleep 500000
		done
		redir_tcp=1
		echo "$(date "+%Y-%m-%d %H:%M:%S") Shadowsocks/ShadowsocksR $threads 线程启动成功!" >>$LOG_FILE
		;;
	trojan)
		for i in $(seq 1 $threads); do
			$bin --config $trojan_json_file >>$LOG_FILE 2>&1 &
			usleep 500000
		done
		echo "$(date "+%Y-%m-%d %H:%M:%S") $($bin --version 2>&1 | head -1) Started!" >>$LOG_FILE
		;;
	v2ray)
		if [ "$UDP_RELAY_SERVER" != "same" ] ; then
		$bin -config $v2_json_file >/dev/null 2>&1 &
		fi
		echo "$(date "+%Y-%m-%d %H:%M:%S") $($bin -version | head -1) 启动成功!" >>$LOG_FILE
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
	
start_redir_udp() {
	if [ "$UDP_RELAY_SERVER" != "nil" ]; then
		redir_udp=1
		logger -t "SS" "启动$utype游戏UDP中继服务器"
		utype=$(nvram get ud_type)
		local bin=$(find_bin $utype)
		[ ! -f "$bin" ] && echo "$(date "+%Y-%m-%d %H:%M:%S") UDP TPROXY Relay:Can't find $bin program, can't start!" >>$LOG_FILE && return 1
		case "$utype" in
		ss | ssr)
			ARG_OTA=""
			gen_config_file $UDP_RELAY_SERVER 1 1080
			last_config_file=$CONFIG_UDP_FILE
			pid_file="/var/run/ssr-reudp.pid"
			$bin -c $last_config_file $ARG_OTA -U -f /var/run/ssr-reudp.pid >/dev/null 2>&1
			;;
		v2ray)
			gen_config_file $UDP_RELAY_SERVER 1
			$bin -config /tmp/v2-ssr-reudp.json >/dev/null 2>&1 &
			;;
		trojan)
			gen_config_file $UDP_RELAY_SERVER 1
			$bin --config /tmp/trojan-ssr-reudp.json >/dev/null 2>&1 &
			ipt2socks -U -b 0.0.0.0 -4 -s 127.0.0.1 -p 10801 -l 1080 >/dev/null 2>&1 &
			;;
		socks5)
		echo "1"
		    ;;
		esac
	fi
	return 0
}

# ================================= 启动 Socks5代理 ===============================
start_local() {
	local s5_port=$(nvram get socks5_port)
	local local_server=$(nvram get socks5_enable)
	[ "$local_server" == "nil" ] && return 1
	[ "$local_server" == "same" ] && local_server=$GLOBAL_SERVER
	local type=$(nvram get s5_type)
	local bin=$(find_bin $type)
	[ ! -f "$bin" ] && echo "$(date "+%Y-%m-%d %H:%M:%S") Global_Socks5:Can't find $bin program, can't start!" >>$LOG_FILE && return 1
	case "$type" in
	ss | ssr)
		local name="Shadowsocks"
		local bin=$(find_bin ss-local)
		[ ! -f "$bin" ] && echo "$(date "+%Y-%m-%d %H:%M:%S") Global_Socks5:Can't find $bin program, can't start!" >>$LOG_FILE && return 1
		[ "$type" == "ssr" ] && name="ShadowsocksR"
		gen_config_file $local_server 3 $s5_port
		$bin -c $CONFIG_SOCK5_FILE -u -f /var/run/ssr-local.pid >/dev/null 2>&1
		echo "$(date "+%Y-%m-%d %H:%M:%S") Global_Socks5:$name Started!" >>$LOG_FILE
		;;
	v2ray)
		lua /etc_ro/ss/genv2config.lua $local_server tcp 0 $s5_port >/tmp/v2-ssr-local.json
		sed -i 's/\\//g' /tmp/v2-ssr-local.json
		$bin -config /tmp/v2-ssr-local.json >/dev/null 2>&1 &
		echo "$(date "+%Y-%m-%d %H:%M:%S") Global_Socks5:$($bin -version | head -1) Started!" >>$LOG_FILE
		;;
	trojan)
		lua /etc_ro/ss/gentrojanconfig.lua $local_server client $s5_port >/tmp/trojan-ssr-local.json
		sed -i 's/\\//g' /tmp/trojan-ssr-local.json
		$bin --config /tmp/trojan-ssr-local.json >/dev/null 2>&1 &
		echo "$(date "+%Y-%m-%d %H:%M:%S") Global_Socks5:$($bin --version 2>&1 | head -1) Started!" >>$LOG_FILE
		;;
	*)
		[ -e /proc/sys/net/ipv6 ] && local listenip='-i ::'
		microsocks $listenip -p $s5_port ssr-local >/dev/null 2>&1 &
		echo "$(date "+%Y-%m-%d %H:%M:%S") Global_Socks5:$type Started!" >>$LOG_FILE
		;;
	esac
	local_enable=1
	return 0
}

rules() {
	[ "$GLOBAL_SERVER" = "nil" ] && return 1
	UDP_RELAY_SERVER=$(nvram get udp_relay_server)
	if [ "$UDP_RELAY_SERVER" = "same" ]; then
	UDP_RELAY_SERVER=$GLOBAL_SERVER
	fi
	if start_rules; then
		return 0
	else
		return 1
	fi
}

auto_update() {
	sed -i '/update_chnroute/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/update_gfwlist/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/update_adblock/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/ss-watchcat/d' /etc/storage/cron/crontabs/$http_username
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

clear_iptable()
{
	s5_port=$(nvram get socks5_port)
	iptables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	iptables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	ip6tables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	ip6tables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	
}

start_watchcat() {
	if [ $(nvram get ss_watchcat) = 1 ]; then
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
	if [ "$UDP_RELAY_SERVER" != "nil" ]; then
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
	dports=$(nvram get s_dports)
	if [ $dports = "0" ]; then
		proxyport=" "
	else
		proxyport="-m multiport --dports 22,53,587,465,995,993,143,80,443,853,9418"
	fi
	get_arg_out() {
		router_proxy="1"
		case "$router_proxy" in
		1) echo "-o" ;;
		2) echo "-O" ;;
		esac
	}
	/usr/bin/ss-rules \
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

# ================================= 启动 SS ===============================
ssp_start() { 
	echolog "----------start------------"
	ulimit -n 65535
    ss_enable=`nvram get ss_enable`
if rules; then
		if start_redir_tcp; then
		start_redir_udp
        #start_rules
		#start_AD
		fi
		fi
        start_local
        start_watchcat
        auto_update
        ENABLE_SERVER=$(nvram get global_server)
        [ "$ENABLE_SERVER" = "-1" ] && return 1

        logger -t "SS" "启动成功。"
        logger -t "SS" "内网IP控制为:$lancons"
        nvram set check_mode=0
}

# ================================= 关闭SS ===============================

ssp_close() {
	/usr/bin/ss-rules -f
	ps -w | grep -v "grep" | grep ssr-monitor | awk '{print $1}' | xargs killall -q -9 >/dev/null 2>&1 &
	ps -w | grep -v "grep" | grep "sleep 0000" | awk '{print $1}' | xargs killall -q -9 >/dev/null 2>&1 &
	kill_process
	rm -f /tmp/ssr-monitor.lock
	sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
	clear_iptable
	/sbin/restart_dhcpd
}

kill_process() {
	v2ray_process=$(pidof xray)
	if [ -n "$v2ray_process" ]; then
		logger -t "SS" "关闭V2Ray进程..."
		killall xray >/dev/null 2>&1
		kill -9 "$v2ray_process" >/dev/null 2>&1
	fi
	ssredir=$(pidof ss-redir)
	if [ -n "$ssredir" ]; then
		logger -t "SS" "关闭ss-redir进程..."
		killall ss-redir >/dev/null 2>&1
		kill -9 "$ssredir" >/dev/null 2>&1
	fi

	rssredir=$(pidof ssr-redir)
	if [ -n "$rssredir" ]; then
		logger -t "SS" "关闭ssr-redir进程..."
		killall ssr-redir >/dev/null 2>&1
		kill -9 "$rssredir" >/dev/null 2>&1
	fi
	
	sslocal_process=$(pidof ss-local)
	if [ -n "$sslocal_process" ]; then
		logger -t "SS" "关闭ss-local进程..."
		killall ss-local >/dev/null 2>&1
		kill -9 "$sslocal_process" >/dev/null 2>&1
	fi

	trojandir=$(pidof trojan)
	if [ -n "$trojandir" ]; then
		logger -t "SS" "关闭trojan进程..."
		killall trojan >/dev/null 2>&1
		kill -9 "$trojandir" >/dev/null 2>&1
	fi

	kumasocks_process=$(pidof kumasocks)
	if [ -n "$kumasocks_process" ]; then
		logger -t "SS" "关闭kumasocks进程..."
		killall kumasocks >/dev/null 2>&1
		kill -9 "$kumasocks_process" >/dev/null 2>&1
	fi
	
	ipt2socks_process=$(pidof ipt2socks)
	if [ -n "$ipt2socks_process" ]; then
		logger -t "SS" "关闭ipt2socks进程..."
		killall ipt2socks >/dev/null 2>&1
		kill -9 "$ipt2socks_process" >/dev/null 2>&1
	fi

	socks5_process=$(pidof srelay)
	if [ -n "$socks5_process" ]; then
		logger -t "SS" "关闭socks5进程..."
		killall srelay >/dev/null 2>&1
		kill -9 "$socks5_process" >/dev/null 2>&1
	fi

	ssrs_process=$(pidof ssr-server)
	if [ -n "$ssrs_process" ]; then
		logger -t "SS" "关闭ssr-server进程..."
		killall ssr-server >/dev/null 2>&1
		kill -9 "$ssrs_process" >/dev/null 2>&1
	fi
	
	cnd_process=$(pidof chinadns-ng)
	if [ -n "$cnd_process" ]; then
		logger -t "SS" "关闭chinadns-ng进程..."
		killall chinadns-ng >/dev/null 2>&1
		kill -9 "$cnd_process" >/dev/null 2>&1
	fi

	dns2tcp_process=$(pidof dns2tcp)
	if [ -n "$dns2tcp_process" ]; then
		logger -t "SS" "关闭dns2tcp进程..."
		killall dns2tcp >/dev/null 2>&1
		kill -9 "$dns2tcp_process" >/dev/null 2>&1
	fi
	
	pdnsd_process=$(pidof pdnsd)
	if [ -n "$pdnsd_process" ]; then
		logger -t "SS" "关闭pdnsd进程..."
		killall pdnsd >/dev/null 2>&1
		kill -9 "$pdnsd_process" >/dev/null 2>&1
	fi
	
	microsocks_process=$(pidof microsocks)
	if [ -n "$microsocks_process" ]; then
		logger -t "SS" "关闭socks5服务端进程..."
		killall microsocks >/dev/null 2>&1
		kill -9 "$microsocks_process" >/dev/null 2>&1
	fi
}


# ================================= 重启 SS ===============================
ressp() {
	BACKUP_SERVER=$(nvram get backup_server)
	start_redir $BACKUP_SERVER
	start_rules $BACKUP_SERVER
	start_local
	start_watchcat
	auto_update
	ENABLE_SERVER=$(nvram get global_server)
	logger -t "SS" "备用服务器启动成功"
	logger -t "SS" "内网IP控制为:$lancons"
}

case $1 in
start)
	ssp_start
	;;
stop)
	#killall -q -9 ssr-switch
	ssp_close
	;;
restart)
	ssp_close
	ssp_start
	;;
reserver)
	ssp_close
	ressp
	;;
*)
	echo "check"
	#exit 0
	;;
esac

