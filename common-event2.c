#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <string.h>
#include <time.h>

#include "common-event2.h"
#include "logging.h"
#include "utils.h"

static void ev_auth_timeout(struct ev_user_data * const user_data)
{
    LOG(NOTICE, "Authentication timeout");
    ev_disconnect(user_data->state);
}

static int ev_add_timer(struct ev_user_data * const user_data, time_t trigger_after)
{
    struct timeval tv;

    LOG(LP_DEBUG, "Added timer event, next trigger in %llus", (unsigned long long int)trigger_after);
    tv.tv_sec = trigger_after;
    tv.tv_usec = 0;
    return event_add(user_data->generic_timer, &tv);
}

static void ev_del_timer(struct ev_user_data * const user_data)
{
    event_del(user_data->generic_timer);
}

static double time_passed(double last_time)
{
    return create_timestamp() - last_time;
}

int ev_default_timeout(struct ev_user_data * const user_data)
{
    if (user_data->state->awaiting_pong >= MAX_AWAITING_PONG) {
        LOG(ERROR, "Max awaiting PONG reached: %u", MAX_AWAITING_PONG);
        ev_disconnect(user_data->state);
        return 0;
    }
    if (time_passed(user_data->state->last_ping_recv) > PING_INTERVAL ||
        time_passed(user_data->state->last_ping_send) > PING_INTERVAL) {
        LOG(NOTICE, "Sending PING");
        if (ev_protocol_ping(user_data->state) != RECV_SUCCESS) {
            LOG(WARNING, "Could not send PING");
            return 1;
        }
    }
    if (ev_add_timer(user_data, PING_INTERVAL + (random() % PING_INTERVAL)) != 0) {
        return 1;
    }
    return 0;
}

static void ev_generic_timer(evutil_socket_t fd, short events, void * arg)
{
    struct ev_user_data * const user_data = (struct ev_user_data *)arg;

    (void)fd;
    (void)events;

    if ((events & EV_TIMEOUT) == 0) {
        return;
    }

    switch (user_data->state->state) {
        case CONNECTION_NEW:
            ev_auth_timeout(user_data);
            break;
        case CONNECTION_AUTH_SUCCESS:
            ev_default_timeout(user_data);
            break;
        case CONNECTION_INVALID:
            ev_del_timer(user_data);
            break;
    }
}

int ev_setup_generic_timer(struct ev_user_data * const user_data, time_t trigger_after)
{
    if (user_data->generic_timer != NULL) {
        event_free(user_data->generic_timer);
        user_data->generic_timer = NULL;
    }
    user_data->generic_timer = event_new(bufferevent_get_base(user_data->bev), -1, 0, ev_generic_timer, user_data);
    if (user_data->generic_timer == NULL) {
        return 1;
    }

    return ev_add_timer(user_data, trigger_after);
}

void ev_cleanup_user_data(struct connection * const state)
{
    struct ev_user_data * user_data;

    user_data = (struct ev_user_data *)state->user_data;

    if (user_data == NULL) {
        return;
    }

    if (user_data->generic_timer != NULL) {
        ev_del_timer(user_data);
        event_free(user_data->generic_timer);
        user_data->generic_timer = NULL;
    }

    if (user_data->bev != NULL) {
        bufferevent_decref(user_data->bev);
        bufferevent_free(user_data->bev);
        user_data->bev = NULL;
    }

    free(user_data);
    state->user_data = NULL;
}

int ev_setup_user_data(struct bufferevent * const bev, struct connection * const state)
{
    struct ev_user_data * udata;

    udata = (struct ev_user_data *)malloc(sizeof(*udata));
    if (udata == NULL) {
        return 1;
    }

    udata->state = state;
    udata->bev = bev;
    udata->generic_timer = NULL;
    state->user_data = udata;

    bufferevent_incref(bev);
    bufferevent_setwatermark(
        bev,
        EV_READ | EV_WRITE,
        (CRYPTO_BYTES_POSTAUTH > CRYPTO_BYTES_PREAUTH ? CRYPTO_BYTES_PREAUTH : CRYPTO_BYTES_POSTAUTH) +
            sizeof(struct protocol_header),
        (CRYPTO_BYTES_POSTAUTH < CRYPTO_BYTES_PREAUTH ? CRYPTO_BYTES_PREAUTH : CRYPTO_BYTES_POSTAUTH) * 2 +
            sizeof(struct protocol_header) + WINDOW_SIZE);

    return 0;
}

void ev_set_io_timeouts(struct bufferevent * const bev)
{
    struct timeval tv;

    tv.tv_sec = INACTIVITY_TIMEOUT;
    tv.tv_usec = 0;
    bufferevent_set_timeouts(bev, &tv, &tv);
}

void ev_sighandler(evutil_socket_t fd, short events, void * arg)
{
    struct event * ev_signal = (struct event *)arg;

    (void)fd;
    (void)events;
    if (ev_signal != NULL) {
        LOG(WARNING, "Got signal %d", event_get_signal(ev_signal));
        event_base_loopexit(event_get_base(ev_signal), NULL);
    }
}

int ev_protocol_client_auth(struct connection * const state, const char * const user, const char * const pass)
{
    int result;
    unsigned char auth_pkt_crypted[CRYPT_PACKET_SIZE_CLIENT_AUTH];
    struct ev_user_data * user_data = (struct ev_user_data *)state->user_data;

    protocol_response_client_auth(auth_pkt_crypted, state, user, pass);
    result = evbuffer_add(bufferevent_get_output(user_data->bev), auth_pkt_crypted, sizeof(auth_pkt_crypted));
    return result;
}

int ev_protocol_server_helo(struct connection * const state, const char * const server_message)
{
    int result;
    unsigned char helo_pkt_crypted[CRYPT_PACKET_SIZE_SERVER_HELO];
    struct ev_user_data * user_data = (struct ev_user_data *)state->user_data;

    protocol_response_server_helo(helo_pkt_crypted, state, server_message);
    result = evbuffer_add(bufferevent_get_output(user_data->bev), helo_pkt_crypted, sizeof(helo_pkt_crypted));
    return result;
}

int ev_protocol_data(struct connection * const state, uint8_t const * const payload, uint32_t payload_size)
{
    int result;
    unsigned char data_pkt_crypted[CRYPT_PACKET_SIZE_DATA + payload_size];
    struct ev_user_data * user_data = (struct ev_user_data *)state->user_data;

    protocol_response_data(data_pkt_crypted, CRYPT_PACKET_SIZE_DATA + payload_size, state, payload, payload_size);
    result = evbuffer_add(bufferevent_get_output(user_data->bev), data_pkt_crypted, sizeof(data_pkt_crypted));

    return result;
}

int ev_protocol_ping(struct connection * const state)
{
    int result;
    unsigned char ping_pkt_crypted[CRYPT_PACKET_SIZE_PING];
    char timestamp[TIMESTAMP_STRLEN];
    struct ev_user_data * user_data = (struct ev_user_data *)state->user_data;

    protocol_response_ping(ping_pkt_crypted, state);

    strftime_local(state->last_ping_send, timestamp, sizeof(timestamp));
    LOG(LP_DEBUG,
        "Sending PING with ts %.09lf: %s / %uns",
        state->last_ping_send,
        timestamp,
        extract_nsecs(state->last_ping_send));
    result = evbuffer_add(bufferevent_get_output(user_data->bev), ping_pkt_crypted, sizeof(ping_pkt_crypted));
    return result;
}

int ev_protocol_pong(struct connection * const state)
{
    int result;
    unsigned char pong_pkt_crypted[CRYPT_PACKET_SIZE_PONG];
    char timestamp[TIMESTAMP_STRLEN];
    struct ev_user_data * user_data = (struct ev_user_data *)state->user_data;

    protocol_response_pong(pong_pkt_crypted, state);
    strftime_local(state->last_pong_send, timestamp, sizeof(timestamp));
    LOG(LP_DEBUG,
        "Sending PONG with ts %.09lf: %s / %uns",
        state->last_pong_send,
        timestamp,
        extract_nsecs(state->last_pong_send));
    result = evbuffer_add(bufferevent_get_output(user_data->bev), pong_pkt_crypted, sizeof(pong_pkt_crypted));
    return result;
}

void ev_disconnect(struct connection * const state)
{
    LOG(LP_DEBUG, "Closing connection");

    if (state == NULL) {
        return;
    }

    on_disconnect(state);
    ev_cleanup_user_data(state);

    if (state->session_keys != NULL) {
        sodium_memzero(state->session_keys, sizeof(*(state->session_keys)));
        free(state->session_keys);
    }

    free(state);
}

void ev_read_cb(struct bufferevent * bev, void * connection_state)
{
    struct connection * const c = (struct connection *)connection_state;
    struct evbuffer * const input = bufferevent_get_input(bev);

    LOG(LP_DEBUG, "Read %d bytes", evbuffer_get_length(input));

    do {
        uint8_t * buf = evbuffer_pullup(input, -1);
        size_t siz = evbuffer_get_length(input);

        switch (process_received(c, buf, &siz)) {
            case RECV_SUCCESS:
                break;
            case RECV_FATAL:
                LOG(ERROR, "Internal error");
                ev_disconnect(c);
                return;
            case RECV_FATAL_UNAUTH:
                LOG(ERROR, "Peer not authenticated");
                ev_disconnect(c);
                return;
            case RECV_FATAL_CRYPTO_ERROR:
                LOG(ERROR, "Crypto error");
                ev_disconnect(c);
                return;
            case RECV_FATAL_REMOTE_WINDOW_SIZE:
                LOG(ERROR, "Remote has a larger WINDOW_SIZE size than us.");
                ev_disconnect(c);
                return;
            case RECV_FATAL_CALLBACK_ERROR:
                LOG(ERROR, "Callback error");
                ev_disconnect(c);
                return;
            case RECV_CORRUPT_PACKET:
                LOG(ERROR, "Packet Corrupt");
                ev_disconnect(c);
                return;
            case RECV_BUFFER_NEED_MORE_DATA:
                LOG(LP_DEBUG, "No more data to read");
#if 0
                /* forced output buffer flushing, not required IMHO as libevent is clever though */
                if (bufferevent_flush(bev, EV_WRITE, BEV_FLUSH) != 0) {
                    LOG(WARNING, "Could not flush output buffer");
                }
#endif
                return;
            case RECV_CALLBACK_NOT_IMPLEMENTED:
                LOG(WARNING, "Callback not implemented");
                ev_disconnect(c);
                return;
        }

        LOG(LP_DEBUG, "Draining input buffer by %zu bytes", siz);
        evbuffer_drain(input, siz);
    } while (1);
}

void ev_write_cb(struct bufferevent * bev, void * connection_state)
{
    (void)connection_state;
    if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
        LOG(LP_DEBUG, "No more data to write");
    } else {
        LOG(LP_DEBUG, "Write %d bytes", evbuffer_get_length(bufferevent_get_output(bev)));
    }
}

static void event_to_string(char ** buffer, size_t * const buffer_size, const char * const str)
{
    int written = snprintf(*buffer, *buffer_size, "%s, ", str);
    if (written > 0) {
        *buffer += written;
        *buffer_size -= (size_t)written;
    }
}

void ev_events_to_string(short events, char * buffer, size_t buffer_size)
{
    size_t orig_size = buffer_size;

    if (events & EV_TIMEOUT) {
        event_to_string(&buffer, &buffer_size, "EV_TIMEOUT");
    }
    if (events & EV_READ) {
        event_to_string(&buffer, &buffer_size, "EV_TIMEOUT");
    }
    if (events & EV_WRITE) {
        event_to_string(&buffer, &buffer_size, "EV_WRITE");
    }
    if (events & EV_SIGNAL) {
        event_to_string(&buffer, &buffer_size, "EV_SIGNAL");
    }
    if (events & EV_PERSIST) {
        event_to_string(&buffer, &buffer_size, "EV_PERSIST");
    }
    if (events & EV_ET) {
        event_to_string(&buffer, &buffer_size, "EV_ET");
    }
    if (events & EV_FINALIZE) {
        event_to_string(&buffer, &buffer_size, "EV_FINALIZE");
    }
    if (events & EV_CLOSED) {
        event_to_string(&buffer, &buffer_size, "EV_CLOSED");
    }

    if (orig_size > buffer_size + 2) {
        *(buffer - 2) = '\0';
    }
}
