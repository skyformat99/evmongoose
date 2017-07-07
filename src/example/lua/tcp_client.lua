#!/usr/bin/lua

local ev = require("ev")
local evmg = require("evmongoose")
local loop = ev.Loop.default

local function ev_handle(con, event, msg)
	if event == evmg.MG_EV_CONNECT then
		--[[
			Detect connection status, If the connection fails, nil is 
			returned and follow an error message is returned,
			Otherwise, return true
		--]]
		print("connection status:", con:connected())
	elseif event == evmg.MG_EV_RECV then
		local data = con:recv()
		con:send("I'm evmongoose:" .. data)
	end
end

local mgr = evmg.init(loop)

-- Supported opt:
-- ssl_cert
-- ssl_key
-- ssl_ca_cert
-- ssl_cipher_suites
local opt  = {}
mgr:connect(ev_handle, "192.168.0.101:8080", opt)

ev.Signal.new(function(loop, sig, revents)
	loop:unloop()
end, ev.SIGINT):start(loop)

loop:loop()

print("exit...")

