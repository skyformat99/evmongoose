#!/usr/bin/lua

local ev = require("ev")
local evmg = require("evmongoose")
--local loop = ev.Loop.default
local loop = ev.Loop.new()

local mgr = evmg.init(loop)

local function ev_handle(nc, event, msg)
	if event ~= evmg.MG_EV_HTTP_REQUEST or msg.uri ~= "/luatest" then
		return false
	end

	mgr:send_head(nc, 200, -1)
	
	mgr:print_http_chunk(nc, "<h1>method:" .. msg.method .. "</h1>")
	mgr:print_http_chunk(nc, "<h1>uri:" .. msg.uri .. "</h1>")
	mgr:print_http_chunk(nc, "<h1>proto:" .. msg.proto .. "</h1>")
	mgr:print_http_chunk(nc, "<h1>query_string:" .. msg.query_string .. "</h1>")
	mgr:print_http_chunk(nc, "<h1>remote_addr:" .. msg.remote_addr .. "</h1>")

	for k, v in pairs(msg.headers) do
		mgr:print_http_chunk(nc, "<h1>" .. k .. ": " .. v ..  "</h1>")
	end

	local body = mgr:get_http_body(msg.hm) or ""

	print(body)
	mgr:print_http_chunk(nc, "<h1>body:" .. body ..  "</h1>")
	
	mgr:print_http_chunk(nc, "")

	return true
end

-- Supported opt:
-- proto						Must be set to "http" for a http or https server, also includes websocket server
-- document_root				Default is "."
-- index_files					Default is "index.html,index.htm,index.shtml,index.cgi,index.php"
-- enable_directory_listing		Default if false
-- debug						If set true, you can deal raw data by MG_EV_RECV
mgr:bind("8000", ev_handle, {proto = "http", enable_directory_listing = true})
print("Listen on http 8000...")

mgr:bind("7443", ev_handle, {proto = "http", ssl_cert = "server.pem", ssl_key = "server.key"})
print("Listen on https 7443...")

ev.Signal.new(function(loop, sig, revents)
	loop:unloop()
end, ev.SIGINT):start(loop)

loop:loop()

mgr:destroy()

print("exit...")
