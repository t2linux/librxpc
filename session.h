#ifndef RXPC_HTTP2_H
#define RXPC_HTTP2_H

#include <nghttp2/nghttp2.h>
#include "stream.h"

struct rxpc_stream;

struct rxpc_session {
    nghttp2_session *session;
    void *transport_data;

    struct rxpc_stream *stream_root;
    struct rxpc_stream *stream_reply;
};

void rxpc_session_init(struct rxpc_session *s);
void rxpc_session_open(struct rxpc_session *s, nghttp2_session_callbacks *cb, void *transport_data, struct rxpc_stream_callbacks *ready_cbs);
int rxpc_session_send_pending(struct rxpc_session *s);
void rxpc_session_terminate(struct rxpc_session *s);

//FIXME
void _rxpc_session_message_debug(struct rxpc_stream *stream, struct rxpc_msg_header *header, const void *data);

nghttp2_session_callbacks *rxpc_session_create_callbacks();

#endif //RXPC_HTTP2_H
