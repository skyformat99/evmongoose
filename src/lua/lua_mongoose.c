#include <pty.h>
#include "lua_mongoose.h"
#include "mongoose.h"
#include "list.h"

#define LOOP_MT    "ev{loop}"
#define UNINITIALIZED_DEFAULT_LOOP (struct ev_loop*)1
#define MONGOOSE_MT "mongoose"
#define MONGOOSE_CONN_MT "mongoose.connection"

#define LUA_MG_F_HTTP	(1 << 0)
#define LUA_MG_F_DEBUG	(1 << 1)

struct lua_mg_connection {
	struct mg_serve_http_opts http_opts;
	struct mg_connection *nc;
	int fufn;
	int callback;
	unsigned flags;
	struct list_head node;
};

struct mg_resolve_async_ctx {
	lua_State *L;
	int callback;
	char domain[128];
};

struct lua_mg_context {
    struct mg_mgr mgr;
    lua_State *L;
	int initialized;
	struct list_head lua_mg_con_list;
};

static struct lua_mg_connection *find_lua_mg_con(struct lua_mg_context *ctx, struct mg_connection *nc)
{
	struct lua_mg_connection *lcon = NULL;
	
	list_for_each_entry(lcon, &ctx->lua_mg_con_list, node) {
		if (lcon->nc == nc)
			return lcon;
	}
	return NULL;
}

static int mg_ctx_destroy(lua_State *L)
{
	struct lua_mg_context *ctx = luaL_checkudata(L, 1, MONGOOSE_MT);
	
	if (ctx->initialized) {
		struct lua_mg_connection *lcon, *tmp;

		list_for_each_entry_safe(lcon, tmp, &ctx->lua_mg_con_list, node) {
			list_del(&lcon->node);
			free(lcon);
		}

		mg_mgr_free(&ctx->mgr);
		ctx->initialized = 0;
	}
    return 0;
}

static int mg_ctx_init(lua_State *L)
{
	struct ev_loop *loop = NULL;
	struct lua_mg_context *ctx = lua_newuserdata(L, sizeof(struct lua_mg_context));
	
	ctx->L = L;
	ctx->initialized = 1;

	INIT_LIST_HEAD(&ctx->lua_mg_con_list);
		
    luaL_getmetatable(L, MONGOOSE_MT);
    lua_setmetatable(L, -2);

	if (lua_gettop(L) > 1) {
		struct ev_loop **tmp = luaL_checkudata(L, 1, LOOP_MT);
		if (tmp && *tmp != UNINITIALIZED_DEFAULT_LOOP)
			loop = *tmp;
	}

	mg_mgr_init(&ctx->mgr, NULL, loop);
	
	return 1;
}

static void ev_http_reply(struct lua_mg_context *ctx, struct mg_connection *nc, void *ev_data)
{
	lua_State *L = ctx->L;
	struct http_message *rsp = (struct http_message *)ev_data;
	int i;
	char tmp[128];

	nc->flags |= MG_F_CLOSE_IMMEDIATELY;

	lua_pushinteger(L, rsp->resp_code);
	lua_setfield(L, -2, "resp_code");

	lua_pushlstring(L, rsp->resp_status_msg.p, rsp->resp_status_msg.len);
	lua_setfield(L, -2, "resp_status_msg");

	lua_newtable(L);

	for (i = 0; rsp->header_names[i].len > 0; i++) {
		struct mg_str *h = &rsp->header_names[i], *v = &rsp->header_values[i];
		if (h->p) {
			lua_pushlstring(L,v->p, v->len);
			snprintf(tmp, sizeof(tmp), "%.*s", (int)h->len, h->p);
			lua_setfield(L, -2, tmp);
		}
	}
	
	lua_setfield(L, -2, "headers");

	lua_pushlstring(L, rsp->body.p, rsp->body.len);
	lua_setfield(L, -2, "body");
	
	lua_call(L, 3, 1);
}

static void ev_http_request(struct lua_mg_context *ctx, struct mg_connection *nc, 
				struct lua_mg_connection *lcon, void *ev_data)
{
	lua_State *L = ctx->L;
	struct http_message *hm = (struct http_message *)ev_data;
	int i;
	char tmp[128];

	lua_pushlstring(L, hm->method.p, hm->method.len);
	lua_setfield(L, -2, "method");
	
	lua_pushlstring(L, hm->uri.p, hm->uri.len);
	lua_setfield(L, -2, "uri");
	
	lua_pushlstring(L, hm->proto.p, hm->proto.len);
	lua_setfield(L, -2, "proto");
	
	lua_pushlstring(L, hm->query_string.p, hm->query_string.len);
	lua_setfield(L, -2, "query_string");
	
	lua_pushinteger(L, (long)hm);
	lua_setfield(L, -2, "hm");

	lua_pushstring(L, inet_ntoa(nc->sa.sin.sin_addr));
	lua_setfield(L, -2, "remote_addr");
	
	lua_newtable(L);

	for (i = 0; hm->header_names[i].len > 0; i++) {
		struct mg_str *h = &hm->header_names[i], *v = &hm->header_values[i];
		if (h->p) {
			lua_pushlstring(L,v->p, v->len);
			snprintf(tmp, sizeof(tmp), "%.*s", (int)h->len, h->p);
			lua_setfield(L, -2, tmp);
		}
	}
	
	lua_setfield(L, -2, "headers");

	lua_call(L, 3, 1);

	if (nc->flags & MG_F_IS_WEBSOCKET)
		return;
	
	if (!lua_toboolean(L, -1))
		mg_serve_http(nc, hm, lcon->http_opts); /* Serve static content */
}

static void ev_websocket_frame(struct lua_mg_context *ctx, struct mg_connection *nc, void *ev_data)
{
	lua_State *L = ctx->L;
	struct websocket_message *wm = (struct websocket_message *)ev_data;

	lua_pushlstring(L, (const char *)wm->data, wm->size);
	lua_setfield(L, -2, "data");
	
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
		
	lua_setfield(L, -2, "op");

	lua_call(L, 3, 1);
}

static struct mg_str http_upload_fname(struct mg_connection *nc, struct mg_str fname)
{
	struct mg_mgr *mgr = nc->mgr;
	struct lua_mg_context *ctx = container_of(mgr, struct lua_mg_context, mgr);
	struct lua_mg_connection *lcon = find_lua_mg_con(ctx, nc->listener);
	lua_State *L = ctx->L;
	const char *name = NULL;

	lua_rawgeti(L, LUA_REGISTRYINDEX , lcon->fufn);

	lua_pushlstring(L, fname.p, fname.len);
	
	lua_call(L, 1, 1);

	name = lua_tostring(L, -1);
	if (!name || name[0] == '\0')
		return mg_mk_str("");
	
	if (mg_vcmp(&fname, name)) {
		return mg_mk_str(strdup(name));
	}
	
	return fname;
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
	struct mg_mgr *mgr = nc->mgr;
	struct lua_mg_context *ctx = container_of(mgr, struct lua_mg_context, mgr);
	struct lua_mg_connection *lcon = find_lua_mg_con(ctx, nc->listener ? nc->listener : nc);
	lua_State *L = ctx->L;
	
	if (!lcon)
		return;

	lua_rawgeti(L, LUA_REGISTRYINDEX , lcon->callback);
	lua_pushinteger(L, (long)nc);

	lua_pushinteger(L, ev);

	lua_newtable(L);

	switch (ev) {
	case MG_EV_POLL:
	case MG_EV_CLOSE:
	case MG_EV_WEBSOCKET_HANDSHAKE_DONE:
	case MG_EV_MQTT_PINGRESP:
	case MG_EV_HTTP_MULTIPART_REQUEST_END:
		lua_call(L, 3, 1);
		break;
	
	case MG_EV_CONNECT: {
		int err = *(int *)ev_data;
		lua_pushboolean(L, !err);
		lua_setfield(L, -2, "connected");

		lua_pushstring(L, strerror(err));
		lua_setfield(L, -2, "err");
		
		lua_call(L, 3, 1);
		break;
	}

	case MG_EV_RECV: {
		if (!(lcon->flags & LUA_MG_F_HTTP) || (lcon->flags & LUA_MG_F_DEBUG)) {
			struct mbuf *io = &nc->recv_mbuf;
			
			lua_pushlstring(L, io->buf, io->len);
			lua_setfield(L, -2, "data");

			lua_call(L, 3, 1);

			if (lua_toboolean(L, -1))
				mbuf_remove(io, io->len);
		}
		break;
	}

	case MG_EV_MQTT_CONNACK: {
		struct mg_mqtt_message *msg = (struct mg_mqtt_message *)ev_data;
		lua_pushinteger(L, msg->connack_ret_code);
		lua_setfield(L, -2, "code");

		switch (msg->connack_ret_code) {
		case MG_EV_MQTT_CONNACK_ACCEPTED:
			lua_pushstring(L, "Connection Accepted");
			break;
		case MG_EV_MQTT_CONNACK_UNACCEPTABLE_VERSION:
			lua_pushstring(L, "Connection Refused: unacceptable protocol version");
			break;
		case MG_EV_MQTT_CONNACK_IDENTIFIER_REJECTED:
			lua_pushstring(L, "Connection Refused: identifier rejected");
			break;
		case MG_EV_MQTT_CONNACK_SERVER_UNAVAILABLE:
			lua_pushstring(L, "Connection Refused: server unavailable");
			break;
		case MG_EV_MQTT_CONNACK_BAD_AUTH:
			lua_pushstring(L, "Connection Refused: bad user name or password");
			break;
		case MG_EV_MQTT_CONNACK_NOT_AUTHORIZED:
			lua_pushstring(L, "Connection Refused: not authorized");
			break;
		default:
			lua_pushstring(L, "Unknown");
			break;
		}
		
		lua_setfield(L, -2, "reason");
		
		lua_call(L, 3, 1);
		break;
	}

	case MG_EV_MQTT_SUBACK:
	case MG_EV_MQTT_PUBACK: {
		struct mg_mqtt_message *msg = (struct mg_mqtt_message *)ev_data;
		lua_pushinteger(L, msg->message_id);
		lua_setfield(L, -2, "message_id");	
		lua_call(L, 3, 1);
		break;
	}

	case MG_EV_MQTT_PUBLISH: {
		struct mg_mqtt_message *msg = (struct mg_mqtt_message *)ev_data;
		lua_pushlstring(L, msg->topic.p, msg->topic.len);
		lua_setfield(L, -2, "topic");
		lua_pushlstring(L, msg->payload.p, msg->payload.len);
		lua_setfield(L, -2, "payload");
		lua_call(L, 3, 1);
		break;
	}

	case MG_EV_HTTP_REQUEST:
	case MG_EV_WEBSOCKET_HANDSHAKE_REQUEST:
		ev_http_request(ctx, nc, lcon,  ev_data);
		break;

	case MG_EV_HTTP_REPLY:
		ev_http_reply(ctx, nc, ev_data);		
		break;

	case MG_EV_HTTP_PART_BEGIN:
	case MG_EV_HTTP_PART_DATA:
	case MG_EV_HTTP_PART_END: {
		if (lcon->fufn > 0)
			mg_file_upload_handler(nc, ev, ev_data, http_upload_fname);
		break;
	}
	
	case MG_EV_WEBSOCKET_FRAME:
	case MG_EV_WEBSOCKET_CONTROL_FRAME:
		ev_websocket_frame(ctx, nc, ev_data);
		break;
		
	default:
		break;
	}

	lua_settop(L, 0);
}

static int lua_mg_bind(lua_State *L)
{
	struct mg_connection *nc;
	struct mg_bind_opts opts;
	struct lua_mg_context *ctx = luaL_checkudata(L, 1, MONGOOSE_MT);
	const char *address = luaL_checkstring(L, 2);
	struct lua_mg_connection *lcon = NULL;
	const char *proto = NULL;
	const char *err;
	
	luaL_checktype(L, 3, LUA_TFUNCTION);
	
	memset(&opts, 0, sizeof(opts));
	opts.error_string = &err;

	lcon = calloc(1, sizeof(struct lua_mg_connection));
	if (!lcon) {
		luaL_error(L, "%s", strerror(errno));
		return 0;
	}

	lcon->fufn = -1;
	
	if (lua_istable(L, 4)) {
		lua_getfield(L, 4, "proto");
		proto = lua_tostring(L, -1);
	
		lua_getfield(L, 4, "document_root");
		lcon->http_opts.document_root = lua_tostring(L, -1);

		lua_getfield(L, 4, "index_files");
		lcon->http_opts.index_files = lua_tostring(L, -1);

		lua_getfield(L, 4, "enable_directory_listing");
		if (!lua_toboolean(L, -1))
			lcon->http_opts.enable_directory_listing = "no";
			
		lua_getfield(L, 4, "url_rewrites");
		lcon->http_opts.url_rewrites = lua_tostring(L, -1);
		
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
		lua_getfield(L, 4, "debug");
		if (lua_toboolean(L, -1))
			lcon->flags |= LUA_MG_F_DEBUG;
	}

	lua_settop(L, 3);
	lcon->callback = luaL_ref(L, LUA_REGISTRYINDEX);
	
	nc = mg_bind_opt(&ctx->mgr, address, ev_handler, opts);
	if (!nc)
		luaL_error(L, "%s", err);

	lcon->nc = nc;

	list_add(&lcon->node, &ctx->lua_mg_con_list);

	if (proto && !strcmp(proto, "http")) {
		mg_set_protocol_http_websocket(nc);
		lcon->flags |= LUA_MG_F_HTTP;
	}

	lua_pushinteger(L, (long)nc);

	return 1;
}

static int lua_mg_connect(lua_State *L)
{
	struct mg_connection *nc;
	struct mg_connect_opts opts;
	struct lua_mg_context *ctx = luaL_checkudata(L, 1, MONGOOSE_MT);
	const char *address = luaL_checkstring(L, 2);
	struct lua_mg_connection *lcon = NULL;
	const char *err;
	
	luaL_checktype(L, 3, LUA_TFUNCTION);
	
	memset(&opts, 0, sizeof(opts));

	opts.error_string = &err;

	lcon = calloc(1, sizeof(struct lua_mg_connection));
	if (!lcon) {
		luaL_error(L, "%s", strerror(errno));
		return 0;
	}
	
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

	lua_settop(L, 3);
	lcon->callback = luaL_ref(L, LUA_REGISTRYINDEX);
	
	nc = mg_connect_opt(&ctx->mgr, address, ev_handler, opts);
	if (!nc) {
		luaL_error(L, "%s", err);
		return 0;
	}

	lcon->nc = nc;	
	list_add(&lcon->node, &ctx->lua_mg_con_list);
		
	lua_pushinteger(L, (long)nc);
	
	return 1;
}

static int lua_mg_connect_http(lua_State *L)
{
	struct mg_connection *nc;
	struct mg_connect_opts opts;
	struct lua_mg_connection *lcon = NULL;
	struct lua_mg_context *ctx = luaL_checkudata(L, 1, MONGOOSE_MT);
	const char *url = luaL_checkstring(L, 2);
	const char *extra_headers = NULL;
	const char *post_data = NULL;
	const char *err;
	
	luaL_checktype(L, 3, LUA_TFUNCTION);
	
	memset(&opts, 0, sizeof(opts));

	opts.error_string = &err;

	lcon = calloc(1, sizeof(struct lua_mg_connection));
	if (!lcon) {
		luaL_error(L, "%s", strerror(errno));
		return 0;
	}
	
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

		lua_getfield(L, 4, "debug");
		if (lua_toboolean(L, -1))
			lcon->flags |= LUA_MG_F_DEBUG;
	}

	lua_settop(L, 3);
	lcon->callback = luaL_ref(L, LUA_REGISTRYINDEX);

	nc = mg_connect_http_opt(&ctx->mgr, ev_handler, opts, url, extra_headers, post_data);
	if (!nc) {
		luaL_error(L, "%s", err);
		return 0;
	}

	lcon->nc = nc;
	lcon->flags |= LUA_MG_F_HTTP;
	list_add(&lcon->node, &ctx->lua_mg_con_list);
	
	lua_pushinteger(L, (long)nc);

	return 1;
}

static void dns_resolve_cb(struct mg_dns_message *msg, void *data, enum mg_resolve_err e)
{
	struct mg_resolve_async_ctx *ctx = (struct mg_resolve_async_ctx *)data;
	lua_State *L = ctx->L;
	int i = 1;
	struct in_addr ina;
	struct mg_dns_resource_record *rr = NULL;		

	lua_rawgeti(L, LUA_REGISTRYINDEX , ctx->callback);

	lua_pushstring(L, ctx->domain);
	
	if ((!msg) || (e != MG_RESOLVE_OK)) {
		lua_pushnil(L);
		
		switch (e) {
		case MG_RESOLVE_NO_ANSWERS:
			lua_pushstring(L, "No answers");
			break;
		case MG_RESOLVE_EXCEEDED_RETRY_COUNT:
			lua_pushstring(L, "Exceeded retry count");
			break;
		case MG_RESOLVE_TIMEOUT:
			lua_pushstring(L, "Timeout");
			break;
		default:
			lua_pushstring(L, "Unknown error");
			break;
		}
		goto ret;
	}

	lua_newtable(L);
	
	while (1) {
		rr = mg_dns_next_record(msg, MG_DNS_A_RECORD, rr);
		if (!rr)
			break;

		if (mg_dns_parse_record_data(msg, rr, &ina, sizeof(ina)))
			break;

		lua_pushstring(L, inet_ntoa(ina));
		lua_rawseti(L, -2, i++);
	}

	lua_pushstring(L, "ok");
ret:
	free(ctx);
	lua_call(L, 3, 0);
}

static int lua_mg_resolve_async(lua_State *L)
{
	struct lua_mg_context *ctx = luaL_checkudata(L, 1, MONGOOSE_MT);
	const char *domain = luaL_checkstring(L, 2);
	struct mg_resolve_async_ctx *data = NULL;
	struct mg_resolve_async_opts opts;
	
	luaL_checktype(L, 3, LUA_TFUNCTION);

	data = calloc(1, sizeof(struct mg_resolve_async_ctx ));
	if (!data)
		luaL_error(L, "%s", strerror(errno));

	data->L = L;
	strcpy(data->domain, domain);

	memset(&opts, 0, sizeof(opts));

	if (lua_istable(L, 4)) {		
		lua_getfield(L, 4, "max_retries");
		opts.max_retries = lua_tointeger(L, -1);

		lua_getfield(L, 4, "timeout");
		opts.timeout = lua_tointeger(L, -1);
	}

	lua_settop(L, 3);
	data->callback = luaL_ref(L, LUA_REGISTRYINDEX);

	mg_resolve_async_opt(&ctx->mgr, domain, MG_DNS_A_RECORD, dns_resolve_cb, data, opts);
	return 0;
}

static int lua_mg_set_protocol_mqtt(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	mg_set_protocol_mqtt(nc);
	return 0;
}

static int lua_mg_send_mqtt_handshake_opt(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	struct mg_send_mqtt_handshake_opts opts;
	char client_id[128] = "";
	
	memset(&opts, 0, sizeof(opts));

	sprintf(client_id, "evmongoose%ld", time(NULL));

	if (lua_istable(L, 3)) {
		lua_getfield(L, 3, "user_name");
		opts.user_name = lua_tostring(L, -1);

		lua_getfield(L, 3, "password");
		opts.password = lua_tostring(L, -1);

		lua_getfield(L, 3, "client_id");
		if (lua_tostring(L, -1))
			strncpy(client_id, lua_tostring(L, -1), sizeof(client_id));

		lua_getfield(L, 3, "clean_session");
		if (lua_toboolean(L, -1))
			opts.flags |= MG_MQTT_CLEAN_SESSION;

		lua_getfield(L, 3, "will_retain");
		if (lua_toboolean(L, -1))
			opts.flags |= MG_MQTT_WILL_RETAIN;
	}

	mg_set_protocol_mqtt(nc);
	mg_send_mqtt_handshake_opt(nc, client_id, opts);
	return 0;
}

static int lua_mg_mqtt_subscribe(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	const char *topic = luaL_checkstring(L, 3);
	int msg_id = lua_tointeger(L, 4);
	struct mg_mqtt_topic_expression topic_expr = {NULL, 0};
	
	topic_expr.topic = topic;
	mg_mqtt_subscribe(nc, &topic_expr, 1, msg_id);
	return 0;
}

static int lua_mg_mqtt_unsubscribe(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	const char *topic = luaL_checkstring(L, 3);
	int msg_id = lua_tointeger(L, 4);
	
	mg_mqtt_unsubscribe(nc, (char **)&topic, 1, msg_id);
	return 0;
}

static int lua_mg_mqtt_publish(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	const char *topic = luaL_checkstring(L, 3);
	size_t len = 0;
	const char *payload = luaL_checklstring(L, 4, &len);
	int msgid = lua_tointeger(L, 5);
	int qos = lua_tointeger(L, 6);
	
	mg_mqtt_publish(nc, topic, msgid, MG_MQTT_QOS(qos), payload, len);
	return 0;
}

static int lua_mg_send_head(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	int status_code = luaL_checkint(L, 3);
	int64_t content_length = luaL_checkint(L, 4);
	const char *extra_headers = lua_tostring(L, 5);
	
	mg_send_head(nc, status_code, content_length, extra_headers);
	return 0;
}

static int lua_mg_http_send_redirect(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	int status_code = luaL_checkint(L, 3);
	const char *location = luaL_checkstring(L, 4);
	const char *extra_headers = lua_tostring(L, 5);

	if (status_code != 301 && status_code != 302)
		luaL_error(L, "\"status_code\" should be either 301 or 302");
	
	mg_http_send_redirect(nc, status_code, mg_mk_str(location), mg_mk_str(extra_headers));

	return 0;
}

static int lua_mg_get_http_var(lua_State *L)
{
	struct http_message *hm = (struct http_message *)(long)luaL_checkinteger(L, 2);
	const char *name = luaL_checkstring(L, 3);
	char value[64] = "";
	
	if (mg_get_http_var(&hm->query_string, name, value, sizeof(value)) > 0)
		lua_pushstring(L, value);
	else if (mg_get_http_var(&hm->body, name, value, sizeof(value)) > 0)
		lua_pushstring(L, value);
	else
		lua_pushnil(L);
	
	return 1;
}

static int lua_mg_get_http_body(lua_State *L)
{
	struct http_message *hm = (struct http_message *)(long)luaL_checkinteger(L, 2);
	
	lua_pushlstring(L, hm->body.p, hm->body.len);
	
	return 1;
}

static int lua_set_fu_fname_fn(lua_State *L)
{
	struct lua_mg_context *ctx = luaL_checkudata(L, 1, MONGOOSE_MT);
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	struct lua_mg_connection *lcon = find_lua_mg_con(ctx, nc);

	if (!lcon) {
		luaL_error(L, "Invalid nc");
		return 0;
	}
	
	luaL_checktype(L, 3, LUA_TFUNCTION);
	lcon->fufn = luaL_ref(L, LUA_REGISTRYINDEX);

	return 0;
}

static int lua_mg_http_reverse_proxy(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	struct http_message *hm = (struct http_message *)(long)luaL_checkinteger(L, 3);
	const char *mount = luaL_checkstring(L, 4);
	const char *upstream = luaL_checkstring(L, 5);

	mg_http_reverse_proxy(nc, hm, mg_mk_str(mount), mg_mk_str(upstream));
	
	return 0;
}

static int lua_mg_print(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	size_t len = 0;
	const char *buf = luaL_checklstring(L, 3, &len);
	
	mg_send(nc, buf, len);
	return 0;
}

static int lua_mg_print_http_chunk(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	size_t len = 0;
	const char *buf = luaL_checklstring(L, 3, &len);
	
	mg_send_http_chunk(nc, buf, len);
	return 0;
}

static int lua_mg_send_websocket_frame(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	size_t len = 0;
	const char *buf = luaL_checklstring(L, 3, &len);
	int op = luaL_checkinteger(L, 4);
	
	mg_send_websocket_frame(nc, op, buf, len);
	return 0;
}

static int lua_mg_send(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	size_t len = 0;
	const char *buf = luaL_checklstring(L, 3, &len);

	mg_send(nc, buf, len);
	return 0;
}

static int lua_set_connection_flags(lua_State *L)
{
	struct mg_connection *nc = (struct mg_connection *)(long)luaL_checkinteger(L, 2);
	nc->flags |= luaL_checkinteger(L, 3);
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

static const luaL_Reg mongoose_meta[] = {
	{"__gc", mg_ctx_destroy},
	{"destroy", mg_ctx_destroy},
	{"bind", lua_mg_bind},
	{"send_head", lua_mg_send_head},
	{"print_http_chunk", lua_mg_print_http_chunk},
	{"http_send_redirect", lua_mg_http_send_redirect},
	{"print", lua_mg_print},	
	{"connect", lua_mg_connect},
	{"connect_http", lua_mg_connect_http},
	{"get_http_var", lua_mg_get_http_var},
	{"get_http_body", lua_mg_get_http_body},
	{"set_fu_fname_fn", lua_set_fu_fname_fn},
	{"http_reverse_proxy", lua_mg_http_reverse_proxy},
	{"resolve_async", lua_mg_resolve_async},
	{"set_protocol_mqtt", lua_mg_set_protocol_mqtt},
	{"send_mqtt_handshake_opt", lua_mg_send_mqtt_handshake_opt},	
	{"mqtt_subscribe", lua_mg_mqtt_subscribe},
	{"mqtt_unsubscribe", lua_mg_mqtt_unsubscribe},
	{"mqtt_publish", lua_mg_mqtt_publish},
	{"send_websocket_frame", lua_mg_send_websocket_frame},
	{"send", lua_mg_send},
	{"set_connection_flags", lua_set_connection_flags},
	{NULL, NULL}
};

static const luaL_Reg mongoose_fun[] = {
	{"init", mg_ctx_init},
	{"forkpty", lua_forkpty},
	{"mg_time", lua_mg_time},
	{NULL, NULL}
};

int luaopen_evmongoose(lua_State *L) 
{
	/* metatable.__index = metatable */
    luaL_newmetatable(L, MONGOOSE_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, mongoose_meta);

	lua_newtable(L);
	luaL_register(L, NULL, mongoose_fun);
	
	EVMG_LUA_ADD_VARIABLE(MG_EV_POLL);
	EVMG_LUA_ADD_VARIABLE(MG_EV_CONNECT);
	EVMG_LUA_ADD_VARIABLE(MG_EV_CLOSE);
	EVMG_LUA_ADD_VARIABLE(MG_EV_RECV);
	
	EVMG_LUA_ADD_VARIABLE(MG_EV_HTTP_REQUEST);
	EVMG_LUA_ADD_VARIABLE(MG_EV_HTTP_REPLY);
	EVMG_LUA_ADD_VARIABLE(MG_EV_HTTP_MULTIPART_REQUEST_END);
	
	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_HANDSHAKE_REQUEST);
	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_HANDSHAKE_DONE);
	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_FRAME);
	EVMG_LUA_ADD_VARIABLE(MG_EV_WEBSOCKET_CONTROL_FRAME);
	
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_CONTINUE);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_TEXT);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_BINARY);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_CLOSE);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_PING);
	EVMG_LUA_ADD_VARIABLE(WEBSOCKET_OP_PONG);
	
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_CONNACK);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_SUBACK);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_PUBACK);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_PUBLISH);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_PINGRESP);
	
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_CONNACK_ACCEPTED);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_CONNACK_UNACCEPTABLE_VERSION);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_CONNACK_IDENTIFIER_REJECTED);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_CONNACK_SERVER_UNAVAILABLE);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_CONNACK_BAD_AUTH);
	EVMG_LUA_ADD_VARIABLE(MG_EV_MQTT_CONNACK_NOT_AUTHORIZED);

	EVMG_LUA_ADD_VARIABLE(MG_F_SEND_AND_CLOSE);
	EVMG_LUA_ADD_VARIABLE(MG_F_CLOSE_IMMEDIATELY);

	luaopen_evmongoose_syslog(L);
	lua_setfield(L, -2, "syslog");
	
    return 1;
}
