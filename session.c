#include "session.h"

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <inttypes.h>
#include <assert.h>
#include <xpc/xpc_serialization.h>
#include <xpc/xpc_debug.h>
#include "stream.h"

static void _rxpc_session_send_settings(struct rxpc_session *s);
static void _rxpc_session_root_stream_opened(struct rxpc_stream *stream);
static void _rxpc_session_reply_stream_opened(struct rxpc_stream *stream);

void rxpc_session_init(struct rxpc_session *s) {
    s->session = NULL;
    s->stream_root = NULL;
    s->stream_reply = NULL;
}

void rxpc_session_open(struct rxpc_session *s, nghttp2_session_callbacks *cb,
		void *transport_data, struct rxpc_stream_callbacks *ready_cbs) {
    struct rxpc_stream_callbacks cbs = {0};
    nghttp2_option *opt;
    s->transport_data = transport_data;
    nghttp2_option_new(&opt);
    nghttp2_option_set_no_http_messaging(opt, 1);
    nghttp2_session_client_new2(&s->session, cb, s, opt);
    nghttp2_option_del(opt);
    _rxpc_session_send_settings(s);

    s->stream_root = rxpc_stream_open(s, ready_cbs);
}

void rxpc_session_terminate(struct rxpc_session *s) {
    // TODO:
}

int rxpc_session_send_pending(struct rxpc_session *s) {
    int ret = nghttp2_session_send(s->session);
    if (ret != 0) {
        fprintf(stderr, "xrpc: session send error: %s\n", nghttp2_strerror(ret));
        return -1;
    }
    return 0;
}

static void _rxpc_session_send_settings(struct rxpc_session *s) {
    int rv;
    nghttp2_settings_entry iv[1] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
    };

    rv = nghttp2_submit_settings(s->session, NGHTTP2_FLAG_NONE, iv, 1);
    if (rv != 0)
        fprintf(stderr, "xrpc: could not submit settings: %s", nghttp2_strerror(rv));
}

void _rxpc_session_message_debug(struct rxpc_stream *stream, struct rxpc_msg_header *header, const void *data) {
    printf("rxpc: got message { type = %u, flags = %u, msg_id = %" PRIu64 " }\n",
            header->type, header->flags, header->msg_id);
    if (header->length > 0) {
        xpc_object_t o = xpc_deserialize(data, header->length);
        xpc_debug_print_stdout(o);
        printf("\n");
        xpc_free(o);
    }
}

static int _rxpc_session_cb_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    struct rxpc_stream *stream = (struct rxpc_stream *)
            nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            //fprintf(stderr, "rxpc: headers received\n");
            if (stream->cbs.opened)
                stream->cbs.opened(stream);
            break;
    }
    return 0;
}

static int _rxpc_session_cb_data_chunk_recv(nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data) {
    size_t tlen;
    struct rxpc_stream *stream = (struct rxpc_stream *)
            nghttp2_session_get_stream_user_data(session, stream_id);
    struct rxpc_msg_header *header = (struct rxpc_msg_header *) stream->recv_header_data;
#ifdef DEBUG_RAW_IO
    printf("rxpc: stream %d: received data chunk\n", stream_id);
    for (int i = 0; i < len; i++)
        printf("%02x ", data[i]);
    printf("\n");
#endif
    while (len > 0) {
        // Read the header if needed
        if (stream->recv_header_pos < sizeof(struct rxpc_msg_header)) {
            if (stream->recv_header_pos == 0 && len >= sizeof(struct rxpc_msg_header)) { // 99% of cases
                *((struct rxpc_msg_header *) stream->recv_header_data) = *((struct rxpc_msg_header *) data);
                stream->recv_header_pos = sizeof(struct rxpc_msg_header);
                data += sizeof(struct rxpc_msg_header);
                len -= sizeof(struct rxpc_msg_header);
            } else {
                tlen = MIN(sizeof(struct rxpc_msg_header) - stream->recv_header_pos, len);
                memcpy(&stream->recv_header_data[stream->recv_header_pos], data, tlen);
                stream->recv_header_pos += tlen;
                data += tlen;
                len -= tlen;
                if (stream->recv_header_pos < sizeof(struct rxpc_msg_header))
                    break; // Incomplete, not enough data to fill the remaining space
            }

            // Validate the header
            if (header->magic != RXPC_MSG_MAGIC) {
                fprintf(stderr, "rxpc: recv bad magic %" PRIx32, header->magic);
                return -1;
            }
            if (header->version != RXPC_MSG_VERSION) {
                fprintf(stderr, "rxpc: recv bad version %" PRIx32, header->version);
                return -1;
            }
            if (header->length > 0x10000) {
                fprintf(stderr, "rxpc: recv message too long: %" PRIu64 "\n", header->length);
                return -1;
            }
#ifdef  DEBUG
            printf("starting data read of %lli\n", header->length);
#endif
        }

        // Read the data
        if (stream->recv_data_pos == 0 && len >= header->length) {
            // No need to copy the data, it's all in the buffer
            assert(stream->recv_data == NULL);
            if (stream->cbs.message)
                stream->cbs.message(stream, header, data);
            data += header->length;
            len -= header->length;
        } else if (len > 0) {
            if (!stream->recv_data)
                stream->recv_data = malloc(header->length);
            tlen = MIN(len, header->length - stream->recv_data_pos);
            memcpy(&stream->recv_data[stream->recv_data_pos], data, tlen);
            data += tlen;
            len -= tlen;
            stream->recv_data_pos += tlen;

            if (stream->recv_data_pos != header->length)
                break; // Incomplete

            if (stream->cbs.message)
                stream->cbs.message(stream, header, stream->recv_data);
        }

        // Message complete, prepare for next message
        stream->recv_header_pos = 0;
        if (stream->recv_data)
            free(stream->recv_data);
        stream->recv_data_pos = 0;
    }
    return 0;
}

static int _rxpc_session_cb_stream_close(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
        void *user_data) {
    int ret;

    fprintf(stderr, "rxpc: stream %d closed with code %d\n", stream_id, error_code);
    ret = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    if (ret != 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    return 0;
}


nghttp2_session_callbacks *rxpc_session_create_callbacks() {
    nghttp2_session_callbacks *callbacks;

    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, _rxpc_session_cb_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, _rxpc_session_cb_data_chunk_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, _rxpc_session_cb_stream_close);

    return callbacks;
}

