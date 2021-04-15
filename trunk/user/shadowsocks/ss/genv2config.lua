local cjson = require "cjson"
local server_section = arg[1]
local proto = arg[2]
local local_port = arg[3] or "0"
local socks_port = arg[4] or "0"
local ssrindext = io.popen("dbus get ssconf_basic_json_" .. server_section)
local servertmp = ssrindext:read("*all")
local server = cjson.decode(servertmp)
local Xray = {}

local log_settings = {
	access = "/tmp/access.log",
	error = "/tmp/error.log",
	loglevel = "info"
}

-- 传入连接
local inbounds_settings = {}

	local inbounds_localin = (local_port ~= "0") and {
		-- listening
		tag = "local-in",
		port = tonumber(local_port),
		protocol = "dokodemo-door",
		settings = {network = proto, followRedirect = true},
		sniffing = {enabled = true, destOverride = {"http", "tls"}}
	} or nil

	local inbounds_socksin = (proto:find("tcp") and socks_port ~= "0") and {
		-- socks
		tag = "socks-in",
		protocol = "socks",
		port = tonumber(socks_port),
		settings = {auth = "noauth", udp = true}
	} or nil

	local inbounds_dnsin = {
			tag = "dns-in",
			port = 5353,
			protocol = "dokodemo-door",
			settings = {
				address = "8.8.8.8",
				port = 53,
				network = "tcp,udp"
			}
	}

table.insert(inbounds_settings,inbounds_localin)
table.insert(inbounds_settings,inbounds_socksin)
table.insert(inbounds_settings,inbounds_dnsin)


local routing_settings = {}
local routing_rules_settings = {}

	local routing_rules_localin = (local_port ~= "0") and {
    	type = "field",
    	inboundTag = {
    		"local-in"
    	},
    	outboundTag = "proxy-out"
	} or nil

	local routing_rules_socksin = (proto == "tcp" and socks_port ~= "0") and {
    	type = "field",
    	inboundTag = {
    		"socks-in"
    	},
    	outboundTag = "proxy-out"
	} or nil

	local routing_rules_dnsin = {
    	type = "field",
    	inboundTag = {
    		"dns-in"
    	},
    	outboundTag = "dns-out"
    	}
    	

table.insert(routing_rules_settings,routing_rules_localin)
table.insert(routing_rules_settings,routing_rules_socksin)
table.insert(routing_rules_settings,routing_rules_dnsin)

routing_settings["rules"] = routing_rules_settings


-- 传出连接
local outbounds_settings = {}

	local outbounds_dnsout = {
		protocol = "dns",
		tag = "dns-out",
		proxySettings = {
			tag = "proxy-out",
			transportLayer = true
		}
	}

	local outbounds_proxyout = {
		tag = "proxy-out",
		protocol = "vmess",
		settings = {
			vnext = {
				{
					address = server.server,
					port = tonumber(server.server_port),
					users = {
						{
							id = server.vmess_id,
							alterId = tonumber(server.alter_id),
							security = server.security
						}
					}
				}
			}
		},
		-- 底层传输配置
		streamSettings = {
			network = server.transport or "tcp",
			security = (server.xtls == '1') and "xtls" or (server.tls == '1') and "tls" or nil,
			tlsSettings = (server.tls == '1' and (server.insecure == "1" or server.tls_host or server.fingerprint)) and {
				-- tls
				fingerprint = server.fingerprint,
				allowInsecure = (server.insecure == "1") and true or nil,
				serverName = server.tls_host
			} or nil,
			xtlsSettings = (server.xtls == '1' and (server.insecure == "1" or server.tls_host)) and {
				-- xtls
				allowInsecure = (server.insecure == "1") and true or nil,
				serverName = server.tls_host
			} or nil,
			tcpSettings = (server.transport == "tcp" and server.tcp_guise == "http") and {
				-- tcp
				header = {
					type = server.tcp_guise,
					request = {
						-- request
						path = {server.http_path} or {"/"},
						headers = {Host = {server.http_host} or {}}
					}
				}
			} or nil,
			kcpSettings = (server.transport == "kcp") and {
				mtu = tonumber(server.mtu),
				tti = tonumber(server.tti),
				uplinkCapacity = tonumber(server.uplink_capacity),
				downlinkCapacity = tonumber(server.downlink_capacity),
				congestion = (server.congestion == "1") and true or false,
				readBufferSize = tonumber(server.read_buffer_size),
				writeBufferSize = tonumber(server.write_buffer_size),
				header = {type = server.kcp_guise}
			} or nil,
			wsSettings = (server.transport == "ws") and (server.ws_path or server.ws_host or server.tls_host) and {
				-- ws
				path = server.ws_path,
				headers = (server.ws_host or server.tls_host) and {
					-- headers
					Host = server.ws_host or server.tls_host
				} or nil
			} or nil,
			httpSettings = (server.transport == "h2") and {
				-- h2
				path = server.h2_path or "",
				host = {server.h2_host} or nil
			} or nil,
			quicSettings = (server.transport == "quic") and {
				-- quic
				security = server.quic_security,
				key = server.quic_key,
				header = {type = server.quic_guise}
			} or nil
		},
		mux = (server.mux == "1" and server.xtls ~= "1") and {
			-- mux
			enabled = true,
			concurrency = tonumber(server.concurrency)
		} or nil
	}

table.insert(outbounds_settings,outbounds_dnsout)
table.insert(outbounds_settings,outbounds_proxyout)

Xray["log"] = log_settings
Xray["inbounds"] = inbounds_settings
Xray["routing"] = routing_settings
Xray["outbounds"] = outbounds_settings

print(cjson.encode(Xray))
