#!/bin/sh
dnsstr="$(nvram get tunnel_forward)"
dnsserver=$(echo "$dnsstr" | awk -F '#' '{print $1}')
dnsport=$(echo "$dnsstr" | awk -F '#' '{print $2}')
pdnsd_genconfig() {	
if [ ! -f /tmp/pdnsd/pdnsd.cache ]; then
    mkdir -p /tmp/pdnsd
    touch /tmp/pdnsd/pdnsd.cache
    chown -R nobody.nogroup /tmp/pdnsd
fi

cat <<-EOF >/tmp/pdnsd.conf
global{
	perm_cache=1024;
	cache_dir="/tmp/pdnsd";
	pid_file="/tmp/pdnsd.pid";
	run_as="nobody";
	server_ip=127.0.0.1;
	server_port=5353;
	status_ctl=on;
	query_method=tcp_only;
	min_ttl=1h;
	max_ttl=1w;
	timeout=10;
	neg_domain_pol=on;
	proc_limit=2;
	procq_limit=8;
	par_queries=1;
}
server{
	label="ssr-usrdns";
	ip=$dnsserver;
	port=$dnsport;
	timeout=6;
	uptest=none;
	interval=10m;
	purge_cache=off;
	reject=::/0;
}
EOF

chmod -R 744 /tmp/pdnsd.conf
	echo "Start PDNSD"
}

dns_close() {
  cat /tmp/pdnsd.pid | xargs kill -9
  echo "Stop PDNSD"
}

dns_start(){
  pdnsd_genconfig
  /usr/bin/pdnsd -c /tmp/pdnsd.conf >/dev/null 2>&1 &
}

case $1 in
start)
	dns_start
	;;
stop)
	dns_close
	;;
*)
	echo "check"
	;;
esac
