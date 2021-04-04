local cjson = require "cjson"
local server_ping = arg[1]
local server_s = arg[2]
local olddb = io.popen("dbus get ssconf_basic_json_" ..server_s)
local old = olddb:read("*all")
old = cjson.decode(old)
old["ping"] = server_ping;
print(cjson.encode(old))
io.popen("dbus set ssconf_basic_json_" ..server_s.. "='" .. cjson.encode(old) .. "'")
io.popen("logger -t 'SS' '节点(" .. old.alias .. ") 延迟:" .. server_ping .. "'")
