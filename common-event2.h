#ifndef COMMON_H
#define COMMON_H 1

#include <event2/event.h>
#include <stdint.h>

struct bufferevent;

#define AUTHENTICATION_TIMEOUT 10
#define INACTIVITY_TIMEOUT 180
#define PING_INTERVAL (INACTIVITY_TIMEOUT / 3)
#define MAX_AWAITING_PONG 3

struct ev_user_data {
    struct event * generic_timer;
    struct connection * state;
    struct bufferevent * bev;
};

extern void on_disconnect(struct connection * const state);

int ev_auth_timeout(struct ev_user_data * const user_data);

int ev_add_timer(struct ev_user_data * const user_data, time_t trigger_after);

int ev_del_timer(struct ev_user_data * const user_data);

__attribute__((warn_unused_result)) int ev_setup_generic_timer(struct ev_user_data * const user_data,
                                                               time_t trigger_after);

void ev_cleanup_user_data(struct connection * const state);

__attribute__((warn_unused_result)) int ev_setup_user_data(struct bufferevent * const bev,
                                                           struct connection * const state);

void ev_set_io_timeouts(struct bufferevent * const bev);

void ev_sighandler(evutil_socket_t fd, short events, void * arg);

__attribute__((warn_unused_result)) int ev_protocol_client_auth(struct connection * const state,
                                                                const char * const user,
                                                                const char * const pass);

__attribute__((warn_unused_result)) int ev_protocol_server_helo(struct connection * const state,
                                                                const char * const server_message);

__attribute__((warn_unused_result)) int ev_protocol_data(struct connection * const state,
                                                         uint8_t const * const payload,
                                                         uint32_t payload_size);

__attribute__((warn_unused_result)) int ev_protocol_ping(struct connection * const state);

__attribute__((warn_unused_result)) int ev_protocol_pong(struct connection * const state);

void ev_disconnect(struct connection * const state);

void ev_read_cb(struct bufferevent * bev, void * connection_state);

void ev_write_cb(struct bufferevent * bev, void * connection_state);

void ev_events_to_string(short events, char * buffer, size_t buffer_size);

#endif
