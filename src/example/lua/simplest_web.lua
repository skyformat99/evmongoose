#!/usr/bin/lua

local ev = require("ev")
local evmg = require("evmongoose")
local loop = ev.Loop.default

local function ev_handle(con, event)
	if event ~= evmg.MG_EV_HTTP_REQUEST then return end

	local uri = con:uri()

	print("uri:", uri)

	if uri ~= "/luatest" then return end

	print("method:", con:method())
	print("proto:", con:proto())
	print("query_string:", con:query_string())
	print("remote_addr:", con:remote_addr())

	local headers = con:headers()
		for k, v in pairs(headers) do
		print(k .. ": ", v)
	end

	local body = con:body()

	if headers["Content-Encoding"] == "gzip" then
		print("Decode Gzip...")
		body = lz.inflate()(body, "finish")
	end

	print("body:", body)

	local rsp = "Hello, I'm Evmongoose"

	local chunk = true
	if chunk then
		con:send_http_head(200, -1)
		con:send_http_chunk(rsp)
		con:send_http_chunk("")
	else
		con:send_http_head(200, #rsp)
		con:send(rsp)
	end
end

local mgr = evmg.init(loop)

-- Supported opt:
-- proto						Must be set to "http" for a http or https server, also includes websocket server
-- document_root				Default is "."
-- index_files					Default is "index.html,index.htm,index.shtml,index.cgi,index.php"
-- enable_directory_listing		Default if false
-- debug						If set true, you can deal raw data by MG_EV_RECV
mgr:listen(ev_handle, "8000", {proto = "http", enable_directory_listing = true})
print("Listen on http 8000...")

mgr:listen(ev_handle, "7443", {proto = "http", ssl_cert = "server.pem", ssl_key = "server.key"})
print("Listen on https 7443...")

ev.Signal.new(function(loop, sig, revents)
	loop:unloop()
end, ev.SIGINT):start(loop)

loop:loop()

print("exit...")
