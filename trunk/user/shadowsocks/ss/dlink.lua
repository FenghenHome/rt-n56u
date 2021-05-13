#!/usr/bin/lua

------------------------------------------------
-- This file is part of the luci-app-ssr-plus subscribe.lua
-- @author William Chan <root@williamchan.me>
------------------------------------------------
require "nixio"
local cjson = require "cjson"
-- these global functions are accessed all the time by the event handler
-- so caching them is worth the effort
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub
local b64decode = nixio.bin.b64decode
local cache = {}
local nodeResult = setmetatable({}, {__index = cache}) -- update result
local name = 'shadowsocksr'
local uciType = 'servers'
local subscribe_url = {}
local i = 1

local tfilter_words = io.popen("echo -n `nvram get ss_keyword`")
local filter_words = tfilter_words:read("*all")

for line in io.lines("/tmp/dlist.txt") do
print(line)
subscribe_url[i] = line
i = i+1
end

local log = function(...)
	print(os.date("%Y-%m-%d %H:%M:%S ") .. table.concat({...}, " "))
	os.execute("logger -t 'SS' '" .. table.concat({ ... }, " ") .. "'")
end
local encrypt_methods_ss = {
	-- aead
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305"
	--[[ stream
	"table",
	"rc4",
	"rc4-md5",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",
	"bf-cfb",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"salsa20",
	"chacha20",
	"chacha20-ietf" ]]
}
-- 分割字符串
local function split(full, sep)
	full = full:gsub("%z", "") -- 这里不是很清楚 有时候结尾带个\0
	local off, result = 1, {}
	while true do
		local nStart, nEnd = full:find(sep, off)
		if not nEnd then
			local res = ssub(full, off, slen(full))
			if #res > 0 then -- 过滤掉 \0
				tinsert(result, res)
			end
			break
		else
			tinsert(result, ssub(full, off, nStart - 1))
			off = nEnd + 1
		end
	end
	return result
end
-- urlencode
local function get_urlencode(c)
	return sformat("%%%02X", sbyte(c))
end

local function urlEncode(szText)
	local str = szText:gsub("([^0-9a-zA-Z ])", get_urlencode)
	str = str:gsub(" ", "+")
	return str
end

local function get_urldecode(h)
	return schar(tonumber(h, 16))
end
local function UrlDecode(szText)
	return szText:gsub("+", " "):gsub("%%(%x%x)", get_urldecode)
end

-- trim
local function trim(text)
	if not text or text == "" then
		return ""
	end
	return (sgsub(text, "^%s*(.-)%s*$", "%1"))
end
-- md5
local function md5(content)
	local stdout = io.popen('echo \"' .. urlEncode(content) .. '\" | md5sum | cut -d \" \" -f1')
	local stdout2 = stdout:read("*all")
	-- assert(nixio.errno() == 0)
	return trim(stdout2)
end
-- base64
local function base64Decode(text)
	local raw = text
	if not text then
		return ''
	end
	text = text:gsub("%z", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	local result = b64decode(text)
	if result then
		return result:gsub("%z", "")
	else
		return raw
	end
end
-- 检查数组(table)中是否存在某个字符值
-- https://www.04007.cn/article/135.html
local function checkTabValue(tab)
	local revtab = {}
	for k,v in pairs(tab) do
		revtab[v] = true
	end
	return revtab
end
-- 处理数据
local function processData(szType, content)
	local result = {type = szType, local_port = 1234, kcp_param = '--nocomp'}
	if szType == 'ssr' then
		local dat = split(content, "/%?")
		local hostInfo = split(dat[1], ':')
		result.server = hostInfo[1]
		result.server_port = hostInfo[2]
		result.protocol = hostInfo[3]
		result.encrypt_method = hostInfo[4]
		result.obfs = hostInfo[5]
		result.password = base64Decode(hostInfo[6])
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			params[t[1]] = t[2]
		end
		result.obfs_param = base64Decode(params.obfsparam)
		result.protocol_param = base64Decode(params.protoparam)
		local group = base64Decode(params.group)
		if group then
			result.alias = "[" .. group .. "] "
		end
		result.alias = result.alias .. base64Decode(params.remarks)
	elseif szType == 'vmess' then
		local info = cjson.decode(content)
		result.type = 'v2ray'
		result.v2ray_protocol = 'vmess'
		result.server = info.add
		result.server_port = info.port
		result.transport = info.net
		result.alter_id = info.aid
		result.vmess_id = info.id
		result.alias = info.ps
		-- result.mux = 1
		-- result.concurrency = 8
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
		end
		if info.net == 'h2' then
			result.h2_host = info.host
			result.h2_path = info.path
		end
		if info.net == 'tcp' then
			if info.type and info.type ~= "http" then
				info.type = "none"
			end
			result.tcp_guise = info.type
			result.http_host = info.host
			result.http_path = info.path
		end
		if info.net == 'kcp' then
			result.kcp_guise = info.type
			result.mtu = 1350
			result.tti = 50
			result.uplink_capacity = 5
			result.downlink_capacity = 20
			result.read_buffer_size = 2
			result.write_buffer_size = 2
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.securty
		end
		if info.security then
			result.security = info.security
		end
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.tls_host = info.host
			result.insecure = 1
		else
			result.tls = "0"
		end
	elseif szType == "ss" then
		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		local info = content:sub(1, idx_sp - 1)
		local hostInfo = split(base64Decode(info), "@")
		local host = split(hostInfo[2], ":")
		local userinfo = base64Decode(hostInfo[1])
		local method = userinfo:sub(1, userinfo:find(":") - 1)
		local password = userinfo:sub(userinfo:find(":") + 1, #userinfo)
		result.alias = UrlDecode(alias)
		result.type = "ss"
		result.server = host[1]
		if host[2]:find("/%?") then
			local query = split(host[2], "/%?")
			result.server_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = t[2]
			end
			if params.plugin then
				local plugin_info = UrlDecode(params.plugin)
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts = plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
				end
			end
		else
			result.server_port = host[2]
		end
		if checkTabValue(encrypt_methods_ss)[method] then
			result.encrypt_method_ss = method
			result.password = password
		else
			-- 1202 年了还不支持 SS AEAD 的屑机场
			result = nil
		end
	elseif szType == "ssd" then
		result.type = "ss"
		result.server = content.server
		result.server_port = content.port
		result.password = content.password
		result.encrypt_method_ss = content.encryption
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_options
		result.alias = "[" .. content.airport .. "] " .. content.remarks
	elseif szType == "trojan" then
		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		local info = content:sub(1, idx_sp - 1)
		local hostInfo = split(info, "@")
		local host = split(hostInfo[2], ":")
		local userinfo = hostInfo[1]
		local password = userinfo
		result.alias = UrlDecode(alias)
		result.type = 'v2ray'
		result.v2ray_protocol = "trojan"
		result.server = host[1]
		-- 按照官方的建议 默认验证ssl证书
		result.insecure = "0"
		result.tls = "1"
		if host[2]:find("?") then
			local query = split(host[2], "?")
			result.server_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = t[2]
			end
			if params.sni then
				-- 未指定peer（sni）默认使用remote addr
				result.tls_host = params.sni
			end
		else
			result.server_port = host[2]
		end
		result.password = password
	elseif szType == "vless" then
		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		local info = content:sub(1, idx_sp - 1)
		local hostInfo = split(info, "@")
		local host = split(hostInfo[2], ":")
		local uuid = hostInfo[1]
		if host[2]:find("?") then
			local query = split(host[2], "?")
			local params = {}
			for _, v in pairs(split(UrlDecode(query[2]), '&')) do
				local t = split(v, '=')
				params[t[1]] = t[2]
			end
			result.alias = UrlDecode(alias)
			result.type = 'v2ray'
			result.v2ray_protocol = 'vless'
			result.server = host[1]
			result.server_port = query[1]
			result.vmess_id = uuid
			result.vless_encryption = params.encryption or "none"
			result.transport = params.type and (params.type == 'http' and 'h2' or params.type) or "tcp"
			if not params.type or params.type == "tcp" then
				if params.security == "xtls" then
					result.xtls = "1"
					result.tls_host = params.sni or host[1]
					result.vless_flow = params.flow
				else
					result.xtls = "0"
				end
			end
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path or "/"
			end
			if params.type == 'http' then
				result.h2_host = params.host or host[1]
				result.h2_path = params.path or "/"
			end
			if params.type == 'kcp' then
				result.kcp_guise = params.headerType or "none"
				result.mtu = 1350
				result.tti = 50
				result.uplink_capacity = 5
				result.downlink_capacity = 20
				result.read_buffer_size = 2
				result.write_buffer_size = 2
				result.seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				result.serviceName = params.serviceName
			end
			
			if params.security == "tls" then
				result.tls = "1"
				result.tls_host = params.sni or host[1]
			else
				result.tls = "0"
			end
		else
			result.server_port = host[2]
		end
	end
	if not result.alias then
		if result.server and result.server_port then
			result.alias = result.server .. ':' .. result.server_port
		else
			result.alias = "NULL"
		end
	end
	-- alias 不参与 hashkey 计算
	local alias = result.alias
	result.alias = nil
	local switch_enable = result.switch_enable
	result.switch_enable = nil
	--print(cjson.encode(result))
	result.hashkey = md5(cjson.encode(result))
	print(result.hashkey)
	result.alias = alias
	result.switch_enable = switch_enable
	return result
end
-- wget
local function wget(url)
	local stdout = io.popen('wget -q --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36" --no-check-certificate -O- "' .. url .. '"')
	local sresult = stdout:read("*all")
	return trim(sresult)
end

local function check_filer(result)
	do
		local filter_word = split(filter_words, "/")
		print(cjson.encode(filter_word))
		for i, v in pairs(filter_word) do
			if result.alias:find(v) then
				-- log('订阅节点关键字过滤:“' .. v ..'” ，该节点被丢弃')
				return true
			end
		end
	end
end

--local execute = function()
	-- exec
	local add, del = 0, 0
	do
		for k, url in ipairs(subscribe_url) do
			local raw = wget(url)
			if #raw > 0 then
				local nodes, szType
				local groupHash = md5(url)
				cache[groupHash] = {}
				tinsert(nodeResult, {})
				local index = #nodeResult
				-- SSD 似乎是这种格式 ssd:// 开头的
				if raw:find('ssd://') then
					szType = 'ssd'
					local nEnd = select(2, raw:find('ssd://'))
					nodes = base64Decode(raw:sub(nEnd + 1, #raw))
					nodes = cjson.decode(nodes)
					local extra = {airport = nodes.airport, port = nodes.port, encryption = nodes.encryption, password = nodes.password}
					local servers = {}
					-- SS里面包着 干脆直接这样
					for _, server in ipairs(nodes.servers) do
						tinsert(servers, setmetatable(server, {__index = extra}))
					end
					nodes = servers
				else
					-- ssd 外的格式
					nodes = split(base64Decode(raw):gsub(" ", "_"), "\n")
				end
				for _, v in ipairs(nodes) do
					if v then
						local result
						if szType == 'ssd' then
							result = processData(szType, v)
						elseif not szType then
							local node = trim(v)
							local dat = split(node, "://")
							if dat and dat[1] and dat[2] then
								local dat3 = ""
								if dat[3] then
									dat3 = "://" .. dat[3]
								end
								if dat[1] == 'ss' or dat[1] == 'trojan' then
									result = processData(dat[1], dat[2] .. dat3)
								else
									result = processData(dat[1], base64Decode(dat[2]))
								end
							end
						else
							log('跳过未知类型: ' .. szType)
						end
						-- log(result)
						if result then
							-- 中文做地址的 也没有人拿中文域名搞，就算中文域也有Puny Code SB 机场
							if not result.server or not result.server_port or result.alias == "NULL" or check_filer(result) or result.server:match("[^0-9a-zA-Z%-%.%s]") then
								log('丢弃无效节点: ' .. result.type .. ' 节点, ' .. result.alias)
							else
								-- log('成功解析: ' .. result.type ..' 节点, ' .. result.alias)
								result.grouphashkey = groupHash
								tinsert(nodeResult[index], result)
								cache[groupHash][result.hashkey] = nodeResult[index][#nodeResult[index]]
							end
						end
					end
				end
				log('成功解析节点数量: ' .. #nodes)
			else
				log(url .. ': 获取内容为空')
			end
		end
	end
	-- diff
	do
		if next(nodeResult) == nil then
			log("更新失败，没有可用的节点信息")
			return
		end
		local add, del = 0, 0
		for line in io.lines("/tmp/dlinkold.txt") do
		newline = line
		local olddb = io.popen("dbus get ssconf_basic_json_" ..line)
		local old = olddb:read("*all")
		--print(#old)
		if #old > 1 then
		old = cjson.decode(old)
				if old.grouphashkey or old.hashkey then -- 没有 hash 的不参与删除
					if not nodeResult[old.grouphashkey] or not nodeResult[old.grouphashkey][old.hashkey] then
						io.popen("dbus remove ssconf_basic_json_" ..i)
						del = del + 1
					else
						local dat = nodeResult[old.grouphashkey][old.hashkey]
						-- 标记一下
						setmetatable(nodeResult[old.grouphashkey][old.hashkey], { __index =  { _ignore = true } })
					end
				else
					if not old.coustom then
						old.alias = old.server .. ':' .. old.server_port
					end
					log('忽略手动添加的节点: ' .. old.alias)
				end
	
			end
		end
		local ssrindext = io.popen('dbus list ssconf_basic_|grep _json_ | cut -d "=" -f1|cut -d "_" -f4|sort -rn|head -n1')
		local ssrindex = ssrindext:read("*all")
		if #ssrindex == 0 then
			ssrindex = 1
		else
		ssrindex = tonumber(ssrindex) + 1
		end

		for k, v in ipairs(nodeResult) do
			for kk, vv in ipairs(v) do
				if not vv._ignore then
					io.popen("dbus set ssconf_basic_json_" .. ssrindex .. "='" .. cjson.encode(vv) .. "'")
					ssrindex = ssrindex + 1
					add = add + 1
				end
			end
		end
		log('新增节点数量: ' .. add, '删除节点数量: ' .. del)
		log('订阅更新成功')
		end
