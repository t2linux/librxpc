#ifndef RXPC_HTTP2_LIBEVENT_H
#define RXPC_HTTP2_LIBEVENT_H

#include "session.h"
#include "stream.h"
#include <event2/bufferevent.h>

struct rxpc_libevent_session {
    struct rxpc_session session;
    struct bufferevent *bev;
    struct rxpc_stream_callbacks *ready_cbs;
};

struct rxpc_libevent_session *rxpc_libevent_session_create(
		struct event_base *evbase, struct rxpc_stream_callbacks *ready_cbs);

#endif //RXPC_HTTP2_LIBEVENT_H
