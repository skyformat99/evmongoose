#include <pty.h>
#include "lua_mongoose.h"
#include "mongoose.h"
#include "list.h"

#define LOOP_MT    "ev{loop}"
#define UNINITIALIZED_DEFAULT_LOOP (struct ev_loop *)1
#define EVMONGOOSE_MT "evmongoose"
#define EVMONGOOSE_CON_MT "evmongoose{con}"

static char *obj_registry = "evmongoose{obj}";

struct lua_mg_connection {
	struct mg_mgr *mgr;
	struct mg_connection *con;
	struct mg_connection *con2;	/* Store Accepted con */
	struct mg_serve_http_opts http_opts;
	void *ev_data;
	unsigned flags;
};
/*
static void lua_print_stack(lua_State *L, const char *info)
{
	int i = 1;
	printf("----------%s----------\n", info);

	for (; i <= lua_gettop(L); i++) {
		printf("%d %s\n", i, lua_typename(L, lua_type(L, i)));
	}
}
*/

/**
 * Create a "registry" of light userdata pointers into the
 * fulluserdata so that we can get handles into the lua objects.
 */
static void create_obj_registry(lua_State *L)
{
    lua_pushlightuserdata(L, &obj_registry);
    lua_newtable(L);

    lua_createtable(L,  0, 1);
    lua_pushliteral(L, "v");
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);

    lua_rawset(L, LUA_REGISTRYINDEX);
}

static struct lua_mg_connection *lua_obj_new(lua_State* L)
{
    struct lua_mg_connection *lcon;

	luaL_checkudata(L, 1, EVMONGOOSE_MT);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	
	lcon = lua_newuserdata(L, sizeof(struct lua_mg_connection));
	luaL_getmetatable(L, EVMONGOOSE_CON_MT);
	lua_setmetatable(L, -2);

	lua_createtable(L, 1, 0);
	lua_pushvalue(L, 2);
    lua_rawseti(L, -2, 1);
	lua_setfenv(L, -2);

	lua_pushlightuserdata(L, &obj_registry);
    lua_rawget(L, LUA_REGISTRYINDEX);

	lua_pushlightuserdata(L, lcon);
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);

	lua_pop(L, 2);

	lcon->mgr = luaL_checkudata(L, 1, EVMONGOOSE_MT);
	
    return lcon;
}

static void lua_mg_ev_handler(struct mg_connection *con, int ev, void *ev_data)
{
	lua_State *L = (lua_State *)con->mgr->user_data;
	struct lua_mg_connection *lcon;

	if (con->listener) {
		lcon = (struct lua_mg_connection *)con->listener->user_data;
		lcon->con2 = con;
	} else {
		lcon = (struct lua_mg_connection *)con->user_data;
		lcon->con2 = NULL;
	}
	
	lcon->ev_data = ev_data;

	lua_pushlightuserdata(L, &obj_registry);
	lua_rawget(L, LUA_REGISTRYINDEX);

	lua_pushlightuserdata(L, lcon);
	lua_rawget(L, -2);

	lua_getfenv(L, -1);
	lua_rawgeti(L, -1, 1);

	lua_insert(L, -3);
	lua_pop(L, 1);

	lua_pushinteger(L, ev);

	lua_pcall(L, 2, 0, 0);
}

/**************************** meta function of mg_mgr ********************************/
static int lua_mg_connect(lua_State *L)
{	
	struct mg_connection *con;
	struct lua_mg_connection *lcon;
	const char *address = lua_tostring(L, 3);
	struct mg_connect_opts opts;
	const char *err;
	
	lcon = lua_obj_new(L);

	memset(&opts, 0, sizeof(opts));
	opts.error_string = &err;
		
	if (lua_istable(L, 4)) {
#if MG_ENABLE_SSL		
		lua_getfield(L, 4, "ssl_cert");
		opts.ssl_cert = lua_tostring(L, -1);
	
		lua_getfield(L, 4, "ssl_key");
		opts.ssl_key = lua_tostring(L, -1);
		
		lua_getfield(L, 4, "ssl_ca_cert");
		opts.ssl_ca_cert = lua_tostring(L, -1);
		
		lua_getfield(L, 4, "ssl_cipher_suites");
		opts.ssl_cipher_suites = lua_tostring(L, -1);
#endif
	}
	con = mg_connect_opt(lcon->mgr, address, lua_mg_ev_handler, opts);
	if (!con)
		return luaL_error(L, "%s", err);
	
	con->user_data = lcon;
	lcon->con = con;

	return 1;
}

static int lua_mg_connect_http(lua_State *L)
{	
	struct mg_connection *con;
	struct lua_mg_connection *lcon;
	const char *url = lua_tostring(L, 3);
	struct mg_connect_opts opts;
	const char *extra_headers = NULL;
	const char *post_data = NULL;
	const char *err;
	
	lcon = lua_obj_new(L);
	
	memset(&opts, 0, sizeof(opts));
	opts.error_string = &err;
	
	if (lua_istable(L, 4)) {
#if MG_ENABLE_SSL		
		lua_getfield(L, 4, "ssl_cert");
		opts.ssl_cert = lua_tostring(L, -1);
	
		lua_getfield(L, 4, "ssl_key");
		opts.ssl_key = lua_tostring(L, -1);
		
		lua_getfield(L, 4, "ssl_ca_cert");
		opts.ssl_ca_cert = lua_tostring(L, -1);
		
		lua_getfield(L, 4, "ssl_cipher_suites");
		opts.ssl_cipher_suites = lua_tostring(L, -1);
#endif
		lua_getfield(L, 4, "extra_headers");
		extra_headers = lua_tostring(L, -1);

		lua_getfield(L, 4, "post_data");
		post_data = lua_tostring(L, -1);
	}
	
	con = mg_connect_http_opt(lcon->mgr, lua_mg_ev_handler, opts, url, extra_headers, post_data);
	if (!con)
		return luaL_error(L, "%s", err);

	con->user_data = lcon;
	lcon->con = con;

	return 1;
}

static int lua_mg_listen(lua_State *L)
{
	struct mg_connection *con;
	struct lua_mg_connection *lcon;
	const char *address = lua_tostring(L, 3);
	struct mg_bind_opts opts;
	const char *proto = NULL;
	const char *err = NULL;
	
	lcon = lua_obj_new(L);
	
	memset(&opts, 0, sizeof(opts));
	opts.error_string = &err;
	
	if (lua_istable(L, 4)) {
#if MG_ENABLE_SSL		
		lua_getfield(L, 4, "ssl_cert");
		opts.ssl_cert = lua_tostring(L, -1);
	
		lua_getfield(L, 4, "ssl_key");
		opts.ssl_key = lua_tostring(L, -1);
		
		lua_getfield(L, 4, "ssl_ca_cert");
		opts.ssl_ca_cert = lua_tostring(L, -1);
		
		lua_getfield(L, 4, "ssl_cipher_suites");
		opts.ssl_cipher_suites = lua_tostring(L, -1);
#endif
		lua_getfield(L, 4, "proto");
		proto = lua_tostring(L, -1);

		if (proto && !strcmp(proto, "http")) {
			lua_getfield(L, 4, "document_root");
			lcon->http_opts.document_root = lua_tostring(L, -1);

			lua_getfield(L, 4, "index_files");
			lcon->http_opts.index_files = lua_tostring(L, -1);

			lua_getfield(L, 4, "enable_directory_listing");
			if (!lua_toboolean(L, -1))
				lcon->http_opts.enable_directory_listing = "no";
				
			lua_getfield(L, 4, "url_rewrites");
			lcon->http_opts.url_rewrites = lua_tostring(L, -1);
		}
	}

	con = mg_bind_opt(lcon->mgr, address, lua_mg_ev_handler, opts);
	if (!con)
		return luaL_error(L, "%s", err);

	con->user_data = lcon;
	lcon->con = con;

	if (proto && !strcmp(proto, "http"))
		mg_set_protocol_http_websocket(con);

	return 1;
}

/**************************** meta function of mg_connection ********************************/
static int lua_mg_set_flags(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	
	con->flags |= luaL_checkinteger(L, 2);
	return 0;
}

/* 
** Detect connection status
** If the connection fails, nil is returned and an error message is returned,
** Otherwise, return true
*/
static int lua_mg_connected(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	int err = *(int *)lcon->ev_data;

	if (err) {
		lua_pushnil(L);
		lua_pushstring(L, strerror(err));
		return 2;
	}
	
	lua_pushboolean(L, 1);
	return 1;
}

/* Get raw data from connection */
static int lua_mg_recv(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	struct mbuf *io = &con->recv_mbuf;

	lua_pushlstring(L, io->buf, io->len);
	mbuf_remove(io, io->len);

	return 1;
}

static int lua_mg_send(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	size_t len = 0;
	const char *buf = luaL_checklstring(L, 2, &len);

	mg_send(con, buf, len);
	return 0;
}

static int lua_mg_send_http_chunk(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	size_t len = 0;
	const char *buf = luaL_checklstring(L, 2, &len);

	mg_send_http_chunk(con, buf, len);
	return 0;
}

static int lua_mg_send_http_head(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	int status_code = luaL_checkinteger(L, 2);
	int content_length = luaL_checkinteger(L, 3);
	const char *extra_headers = lua_tostring(L, 4);

	mg_send_head(con, status_code, content_length, extra_headers);
	return 0;
}

static int lua_mg_send_http_redirect(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	int status_code = luaL_checkinteger(L, 2);
	const char *location = luaL_checkstring(L, 3);
	const char *extra_headers = lua_tostring(L, 4);

	if (status_code != 301 && status_code != 302)
		luaL_error(L, "\"status_code\" should be either 301 or 302");
	
	mg_http_send_redirect(con, status_code, mg_mk_str(location), mg_mk_str(extra_headers));
	return 0;
}

static int lua_mg_resp_code(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;

	lua_pushinteger(L, hm->resp_code);
	return 1;
}

static int lua_mg_resp_status_msg(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;

	lua_pushlstring(L, hm->resp_status_msg.p, hm->resp_status_msg.len);
	return 1;
}

static int lua_mg_http_headers(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;
	int i;
	char tmp[128];

	lua_newtable(L);

	for (i = 0; hm->header_names[i].len > 0; i++) {
		struct mg_str *h = &hm->header_names[i];
		struct mg_str *v = &hm->header_values[i];
		if (h->p) {
			lua_pushlstring(L, v->p, v->len);
			snprintf(tmp, sizeof(tmp), "%.*s", (int)h->len, h->p);
			lua_setfield(L, -2, tmp);
		}
	}
	return 1;
}

static int lua_mg_http_method(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;

	lua_pushlstring(L, hm->method.p, hm->method.len);
	return 1;
}

static int lua_mg_http_uri(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;

	lua_pushlstring(L, hm->uri.p, hm->uri.len);
	return 1;
}

static int lua_mg_http_proto(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;
	
	lua_pushlstring(L, hm->proto.p, hm->proto.len);
	return 1;
}

static int lua_mg_http_query_string(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;
	
	lua_pushlstring(L, hm->query_string.p, hm->query_string.len);
	return 1;
}

static int lua_mg_http_remote_addr(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	lua_pushstring(L, inet_ntoa(con->sa.sin.sin_addr));
	return 1;
}

static int lua_mg_http_body(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct http_message *hm = (struct http_message *)lcon->ev_data;

	lua_pushlstring(L, hm->body.p, hm->body.len);
	return 1;
}

static int lua_mg_websocket_op(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct websocket_message *wm = (struct websocket_message *)lcon->ev_data;

	if (wm->flags & WEBSOCKET_OP_CONTINUE)
		lua_pushinteger(L, WEBSOCKET_OP_CONTINUE);
	else if (wm->flags & WEBSOCKET_OP_TEXT)
		lua_pushinteger(L, WEBSOCKET_OP_TEXT);
	else if (wm->flags & WEBSOCKET_OP_BINARY)
		lua_pushinteger(L, WEBSOCKET_OP_BINARY);
	else if (wm->flags & WEBSOCKET_OP_CLOSE)
		lua_pushinteger(L, WEBSOCKET_OP_CLOSE);
	else if (wm->flags & WEBSOCKET_OP_PING)
		lua_pushinteger(L, WEBSOCKET_OP_PING);
	else if (wm->flags & WEBSOCKET_OP_PONG)
		lua_pushinteger(L, WEBSOCKET_OP_PONG);
	else
		lua_pushinteger(L, -1);
	
	return 1;
}

static int lua_mg_websocket_frame(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct websocket_message *wm = (struct websocket_message *)lcon->ev_data;

	lua_pushlstring(L, (const char *)wm->data, wm->size);
	return 1;
}

static int lua_mg_send_websocket_frame(lua_State *L)
{
	struct lua_mg_connection *lcon = luaL_checkudata(L, 1, EVMONGOOSE_CON_MT);
	struct mg_connection *con = lcon->con2 ? lcon->con2 : lcon->con;
	size_t len = 0;
	const char *buf = luaL_checklstring(L, 2, &len);
	int op = luaL_checkinteger(L, 3);

	mg_send_websocket_frame(con, op, buf, len);
	return 0;
}


/*************************evmongoose global function*******************************************/
static int lua_mg_mgr_init(lua_State *L)
{
	struct ev_loop *loop = NULL;
	struct mg_mgr *mgr = lua_newuserdata(L, sizeof(struct mg_mgr));

	luaL_getmetatable(L, EVMONGOOSE_MT);
	lua_setmetatable(L, -2);
	
	if (lua_gettop(L) > 1) {
		struct ev_loop **tmp = luaL_checkudata(L, 1, LOOP_MT);
		if (*tmp != UNINITIALIZED_DEFAULT_LOOP)
			loop = *tmp;
	}
	mg_mgr_init(mgr, L, loop);

	return 1;
}

static int lua_mg_mgr_free(lua_State *L)
{
#if 0
	struct mg_mgr *mgr = luaL_checkudata(L, 1, EVMONGOOSE_MT);
	mg_mgr_free(mgr);
#endif	
	return 0;
}

static int lua_forkpty(lua_State *L)
{
	pid_t pid;
	int pty;
	
	if (lua_gettop(L)) {
		struct termios t;
			
		luaL_checktype(L, 1, LUA_TTABLE);
		
		memset(&t, 0, sizeof(t));
		
		lua_getfield(L, 1, "iflag"); t.c_iflag = luaL_optinteger(L, -1, 0);
		lua_getfield(L, 1, "oflag"); t.c_oflag = luaL_optinteger(L, -1, 0);
		lua_getfield(L, 1, "cflag"); t.c_cflag = luaL_optinteger(L, -1, 0);
		lua_getfield(L, 1, "lflag"); t.c_lflag = luaL_optinteger(L, -1, 0);
		
		lua_getfield(L, 1, "cc");
		if (!lua_isnoneornil(L, -1)) {
			luaL_checktype(L, -1, LUA_TTABLE);
			for (int i = 0; i < NCCS; i++) {
				lua_pushinteger(L, i);
				lua_gettable(L, -2);
				t.c_cc[i] = luaL_optinteger(L, -1, 0);
				lua_pop(L, 1);
			}
		}
		pid = forkpty(&pty, NULL, &t, NULL);
	} else {
		pid = forkpty(&pty, NULL, NULL, NULL);
	}
	
	if (pid < 0) 
		luaL_error(L, strerror(errno));

	lua_pushinteger(L, pid);
	lua_pushinteger(L, pty);
	
	return 2;
}

static int lua_mg_time(lua_State *L)
{
	lua_pushnumber(L, mg_time());
	return 1;
}

static const luaL_Reg evmongoose_con_meta[] = {
	{"set_flags", lua_mg_set_flags},
	{"connected", lua_mg_connected},
	{"recv", lua_mg_recv},
	{"send", lua_mg_send},
	{"send_http_chunk", lua_mg_send_http_chunk},
	{"send_http_head", lua_mg_send_http_head},
	{"send_http_redirect", lua_mg_send_http_redirect},
	{"resp_code", lua_mg_resp_code},
	{"resp_status_msg", lua_mg_resp_status_msg},
	{"method", lua_mg_http_method},
	{"uri", lua_mg_http_uri},
	{"proto", lua_mg_http_proto},
	{"query_string", lua_mg_http_query_string},
	{"remote_addr", lua_mg_http_remote_addr},
	{"headers", lua_mg_http_headers},
	{"body", lua_mg_http_body},
	{"websocket_op", lua_mg_websocket_op},
	{"websocket_frame", lua_mg_websocket_frame},
	{"send_websocket_frame", lua_mg_send_websocket_frame},
	{NULL, NULL}
};

static const luaL_Reg evmongoose_meta[] = {
	{"connect", lua_mg_connect},
	{"connect_http", lua_mg_connect_http},
	{"listen", lua_mg_listen},
	{"__gc", lua_mg_mgr_free},
	{NULL, NULL}
};

static const luaL_Reg evmongoose_fun[] = {
	{"init", lua_mg_mgr_init},
	{"forkpty", lua_forkpty},
	{"mg_time", lua_mg_time},
	{NULL, NULL}
};

int luaopen_evmongoose(lua_State *L) 
{
	create_obj_registry(L);
	
	/* metatable.__index = metatable */
    luaL_newmetatable(L, EVMONGOOSE_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, evmongoose_meta);

	luaL_newmetatable(L, EVMONGOOSE_CON_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, evmongoose_con_meta);

	lua_newtable(L);
	luaL_register(L, NULL, evmongoose_fun);

	luaopen_evmongoose_syslog(L);
	lua_setfield(L, -2, "syslog");

	EVMG_LUA_ADD_VARIABLE(MG_EV_POLL);    /* Sent to each connection on 1s interval */
	EVMG_LUA_ADD_VARIABLE(MG_EV_ACCEPT);  /* New connection accepted. union socket_address * */
	EVMG_LUA_ADD_VARIABLE(MG_EV_CONNECT); /* connect() succeeded or failed. int *  */
	EVMG_LUA_ADD_VARIABLE(MG_EV_RECV);    /* Data has benn received. int *num_bytes */
	EVMG_LUA_ADD_VARIABLE(MG_EV_SEND);    /* Data has been written to a socket. int *num_bytes */
	EVMG_LUA_ADD_VARIABLE(MG_EV_CLOSE);   /* Connection is closed. NULL */
	EVMG_LUA_ADD_VARIABLE(MG_EV_TIMER);   /* now >= conn->ev_timer_time. double * */

	EVMG_LUA_ADD_VARIABLE(MG_EV_HTTP_REQUEST);
	EVMG_LUA_ADD_VARIABLE(MG_EV_HTTP_REPLY);
	EVMG_LUA_ADD_VARIABLE(MG_EV_HTTP_CHUNK);
	
	EVMG_LUA_ADD_VARIABLE(MG_F_SEND_AND_CLOSE);		/* Push remaining data and close  */
	EVMG_LUA_ADD_VARIABLE(MG_F_CLOSE_IMMEDIATELY);	/* Disconnect */

	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_CONTINUE);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_TEXT);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_BINARY);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_CLOSE);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_PING);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_PONG);

	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_HANDSHAKE_REQUEST);
	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_HANDSHAKE_DONE);
	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_FRAME);
	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_CONTROL_FRAME);
	
    return 1;
}
