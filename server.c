#include <arpa/inet.h>
#include <errno.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common-event2.h"
#include "common-sodium.h"
#include "logging.h"
#include "protocol.h"
#include "utils.h"

static struct cmd_options opts = {.key_string = NULL, .key_length = 0, .host = NULL, .port = 0, .filepath = NULL};
static int data_fd = -1;

static void recv_data(uint8_t const * const buffer, size_t size)
{
    ssize_t bytes_written;

    if (data_fd >= 0) {
        bytes_written = write(data_fd, buffer, size);
        if (bytes_written < 0) {
            LOG(WARNING, "Closing file descriptor %d aka %s: %s", data_fd, opts.filepath, strerror(errno));
            close(data_fd);
            data_fd = -1;
        } else {
            LOG(NOTICE, "Recv DATA: %zd", bytes_written);
        }
    }
}

enum recv_return protocol_request_client_auth(struct connection * const state,
                                              struct protocol_header const * const buffer,
                                              size_t * const processed)
{
    struct protocol_client_auth const * const auth_pkt = (struct protocol_client_auth *)buffer;

    (void)processed;
    LOG(NOTICE, "Client AUTH with protocol version 0x%X", state->used_protocol_version);

    /* user/pass authentication part - exemplary */
    if (strncmp(auth_pkt->login, "username", sizeof(auth_pkt->login)) == 0 &&
        strncmp(auth_pkt->passphrase, "passphrase", sizeof(auth_pkt->passphrase)) == 0) {

        LOG(NOTICE,
            "Username '%.*s' with passphrase '%.*s' logged in",
            sizeof(auth_pkt->login),
            auth_pkt->login,
            sizeof(auth_pkt->passphrase),
            auth_pkt->passphrase);
    } else {
        LOG(ERROR, "Authentication failed, username/passphrase mismatch");
        return RECV_FATAL_UNAUTH;
    }

    log_bin2hex_sodium(NOTICE,
                       "Client AUTH with PublicKey",
                       auth_pkt->client_publickey,
                       sizeof(auth_pkt->client_publickey));
    if (init_crypto_server(state, auth_pkt->server_rx_header, sizeof(auth_pkt->server_rx_header)) != 0) {
        LOG(ERROR, "Client session keypair generation failed");
        return RECV_FATAL_CRYPTO_ERROR;
    }

    if (ev_protocol_server_helo(state, "Welcome.") != 0) {
        LOG(ERROR, "Server AUTH response failed");
        return RECV_FATAL_CALLBACK_ERROR;
    }
    if (ev_setup_generic_timer((struct ev_user_data *)state->user_data, PING_INTERVAL) != 0) {
        LOG(ERROR, "Timer init failed");
        return RECV_FATAL_CALLBACK_ERROR;
    }

    state->state = CONNECTION_AUTH_SUCCESS;
    return RECV_SUCCESS;
}

enum recv_return protocol_request_server_helo(struct connection * const state,
                                              struct protocol_header const * const buffer,
                                              size_t * const processed)
{
    (void)state;
    (void)buffer;
    (void)processed;
    return RECV_CALLBACK_NOT_IMPLEMENTED;
}

enum recv_return protocol_request_data(struct connection * const state,
                                       struct protocol_header const * const buffer,
                                       size_t * const processed)
{
    struct protocol_data const * const data_pkt = (struct protocol_data *)buffer;
    char response[32];

    (void)state;
    (void)processed;
    LOG(NOTICE, "Received DATA with size: %u", data_pkt->header.body_size);
    log_bin2hex_sodium(LP_DEBUG, "DATA", data_pkt->payload, data_pkt->header.body_size);
    recv_data(data_pkt->payload, data_pkt->header.body_size);
    snprintf(response, sizeof(response), "DATA OK: RECEIVED %u BYTES", data_pkt->header.body_size);
    if (ev_protocol_data(state, (uint8_t *)response, sizeof(response)) != 0) {
        return RECV_FATAL_CALLBACK_ERROR;
    }
    return RECV_SUCCESS;
}

enum recv_return protocol_request_ping(struct connection * const state,
                                       struct protocol_header const * const buffer,
                                       size_t * const processed)
{
    struct protocol_ping const * const ping_pkt = (struct protocol_ping *)buffer;

    (void)processed;
    LOG(NOTICE,
        "Received PING with timestamp: %.*s / %lluus",
        sizeof(ping_pkt->timestamp),
        ping_pkt->timestamp,
        state->last_ping_recv_usec);
    if (state->latency_usec > 0.0) {
        LOG(NOTICE, "PING-PONG latency: %.02lfms", state->latency_usec / 1000.0);
    }

    if (ev_protocol_pong(state) != 0) {
        return RECV_FATAL_CALLBACK_ERROR;
    } else {
        return RECV_SUCCESS;
    }
}

enum recv_return protocol_request_pong(struct connection * const state,
                                       struct protocol_header const * const buffer,
                                       size_t * const processed)
{
    struct protocol_pong const * const pong_pkt = (struct protocol_pong *)buffer;

    (void)processed;
    LOG(NOTICE,
        "Received PONG with timestamp: %.*s / %lluus / %zu outstanding PONG's",
        sizeof(pong_pkt->timestamp),
        pong_pkt->timestamp,
        state->last_pong_recv_usec,
        state->awaiting_pong);

    return RECV_SUCCESS;
}

void on_disconnect(struct connection * const state)
{
    char pretty_bytes_rx[16];
    char pretty_bytes_tx[16];

    LOG(NOTICE,
        "Client closed connection; received %s; sent %s",
        prettify_bytes_with_units(pretty_bytes_rx, sizeof(pretty_bytes_rx), state->total_bytes_recv),
        prettify_bytes_with_units(pretty_bytes_tx, sizeof(pretty_bytes_tx), state->total_bytes_sent));
    (void)state;
}

static void event_cb(struct bufferevent * bev, short events, void * con)
{
    struct connection * const c = (struct connection *)con;
    char events_string[64] = {0};

    ev_events_to_string(events, events_string, sizeof(events_string));
    LOG(LP_DEBUG, "Event(s): 0x%02X (%s)", events, events_string);

    if (events & BEV_EVENT_ERROR) {
        LOG(ERROR, "Error from bufferevent: %s", strerror(errno));
        ev_disconnect(c);
        return;
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        ev_disconnect(c);
        return;
    }
    if (events & EV_TIMEOUT) {
        LOG(NOTICE, "Timeout");
        bufferevent_enable(bev, EV_READ | EV_WRITE);
        ev_disconnect(c);
        return;
    }
}

static void accept_conn_cb(
    struct evconnlistener * listener, evutil_socket_t fd, struct sockaddr * address, int socklen, void * user_data)
{
    struct connection * c;
    struct event_base * base;
    struct bufferevent * bev;
    char ip_str[INET6_ADDRSTRLEN + 1];
    struct longterm_keypair const * my_keypair;

    (void)address;
    (void)socklen;

    if (user_data == NULL) {
        return;
    }
    my_keypair = (struct longterm_keypair *)user_data;

    base = evconnlistener_get_base(listener);
    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);

    if (bev == NULL) {
        return;
    }

    c = new_connection_from_client(my_keypair);
    if (c == NULL) {
        bufferevent_free(bev);
        return;
    }

    if (ev_setup_user_data(bev, c) != 0 ||
        ev_setup_generic_timer((struct ev_user_data *)c->user_data, AUTHENTICATION_TIMEOUT) != 0) {
        ev_disconnect(c);
        return;
    }

    bufferevent_setcb(bev, ev_read_cb, ev_write_cb, event_cb, c);
    if (bufferevent_enable(bev, EV_READ | EV_WRITE) != 0) {
        ev_disconnect(c);
        return;
    }
    ev_set_io_timeouts(bev);

    if (inet_ntop(AF_INET, &((struct sockaddr_in *)address)->sin_addr, ip_str, INET_ADDRSTRLEN) == NULL &&
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)address)->sin6_addr, ip_str, INET6_ADDRSTRLEN) == NULL) {
        ip_str[0] = '\0';
    }
    LOG(NOTICE, "Accepted %s:%u", ip_str, ntohs(((struct sockaddr_in6 *)address)->sin6_port));
}

static void accept_error_cb(struct evconnlistener * listener, void * ctx)
{
    struct event_base * base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();

    (void)ctx;
    LOG(ERROR, "Got an error %d (%s) on the listener.", err, evutil_socket_error_to_string(err));
    event_base_loopexit(base, NULL);
}

static void cleanup(struct event_base ** const ev_base,
                    struct evconnlistener ** const ev_listener,
                    struct event ** const ev_sig,
                    struct longterm_keypair ** const my_keypair)
{
    if (*my_keypair != NULL) {
        free(*my_keypair);
    }
    if (*ev_sig != NULL) {
        event_free(*ev_sig);
    }
    if (*ev_listener != NULL) {
        evconnlistener_free(*ev_listener);
    }
    if (*ev_base != NULL) {
        event_base_free(*ev_base);
    }
    *my_keypair = NULL;
    *ev_sig = NULL;
    *ev_listener = NULL;
    *ev_base = NULL;
}

__attribute__((noreturn)) static void cleanup_and_exit(struct event_base ** const ev_base,
                                                       struct evconnlistener ** const ev_listener,
                                                       struct event ** const ev_sigint,
                                                       struct longterm_keypair ** const my_keypair,
                                                       int exit_code)
{
    LOG(LP_DEBUG, "Cleanup and exit with exit code: %d", exit_code);
    cleanup(ev_base, ev_listener, ev_sigint, my_keypair);
    exit(exit_code);
}

int main(int argc, char ** argv)
{
    struct addrinfo * connect_addresses = NULL;
    struct addrinfo * ai;
    int gai_errno;
    struct longterm_keypair * my_keypair = NULL;
    struct event_base * ev_base = NULL;
    struct event * ev_sig = NULL;
    struct evconnlistener * ev_listener = NULL;
    char ip_str[INET6_ADDRSTRLEN + 1];

    parse_cmdline(&opts, argc, argv);
    if (opts.key_string != NULL && opts.key_length != crypto_kx_PUBLICKEYBYTES * 2 /* hex string */) {
        LOG(ERROR, "Invalid server private key length: %zu", opts.key_length);
        return 1;
    }
    if (opts.filepath != NULL) {
        data_fd = open(opts.filepath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (data_fd < 0) {
            LOG(ERROR, "File '%s' open() error: %s", opts.filepath, strerror(errno));
            return 1;
        }
    }
    if (opts.host == NULL || opts.port == NULL) {
        LOG(ERROR, "Invalid host/port");
        return 2;
    }
    LOG(NOTICE, "Resolving %s:%s..", opts.host, opts.port);
    gai_errno = hostname_to_address(opts.host, opts.port, &connect_addresses);
    if (gai_errno != 0) {
        LOG(ERROR, "Address/Service translation error for %s:%s: %s", opts.host, opts.port, gai_strerror(gai_errno));
        return 2;
    }

    srandom(time(NULL));

    if (sodium_init() != 0) {
        LOG(ERROR, "Sodium init failed");
        return 2;
    }

    if (opts.key_string != NULL) {
        my_keypair = generate_keypair_from_secretkey_hexstr_sodium(opts.key_string, opts.key_length);
    } else {
        LOG(NOTICE, "No private key set via command line, generating a new keypair..");
        my_keypair = generate_keypair_sodium();
    }
    if (my_keypair == NULL) {
        LOG(ERROR, "Sodium keypair generation failed");
        cleanup_and_exit(&ev_base, &ev_listener, &ev_sig, &my_keypair, 4);
    }
    if (opts.key_string == NULL) {
        log_bin2hex_sodium(NOTICE, "Server PrivateKey", my_keypair->secretkey, sizeof(my_keypair->secretkey));
    }
    log_bin2hex_sodium(NOTICE, "Server PublicKey", my_keypair->publickey, sizeof(my_keypair->publickey));

    ev_base = event_base_new();
    if (ev_base == NULL) {
        LOG(ERROR, "Couldn't open event base");
        cleanup_and_exit(&ev_base, &ev_listener, &ev_sig, &my_keypair, 5);
    }

    ev_sig = evsignal_new(ev_base, SIGINT, ev_sighandler, event_self_cbarg());
    if (ev_sig == NULL) {
        cleanup_and_exit(&ev_base, &ev_listener, &ev_sig, &my_keypair, 6);
    }
    if (event_add(ev_sig, NULL) != 0) {
        cleanup_and_exit(&ev_base, &ev_listener, &ev_sig, &my_keypair, 7);
    }

    for (ai = connect_addresses; ai != NULL; ai = ai->ai_next) {
        struct sockaddr * sa = NULL;
        socklen_t sl = 0;

        switch (ai->ai_family) {
            case AF_INET:
                sa = (struct sockaddr *)&((struct sockaddr_in *)ai->ai_addr)->sin_addr;
                sl = sizeof(struct sockaddr_in);
                break;
            case AF_INET6:
                sa = (struct sockaddr *)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
                sl = sizeof(struct sockaddr_in6);
                break;
            default:
                LOG(ERROR, "Unknown address family: %d", ai->ai_family);
                cleanup_and_exit(&ev_base, &ev_listener, &ev_sig, &my_keypair, 8);
        }
        if (inet_ntop(ai->ai_family, sa, ip_str, sl) == NULL) {
            LOG(WARNING, "Invalid IPv4 host");
            continue;
        }

        LOG(NOTICE, "Listening on %s:%s", ip_str, opts.port);
        ev_listener = evconnlistener_new_bind(ev_base,
                                              accept_conn_cb,
                                              my_keypair,
                                              LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                              -1,
                                              ai->ai_addr,
                                              ai->ai_addrlen);
        if (ev_listener != NULL) {
            break;
        }
    }
    freeaddrinfo(connect_addresses);
    connect_addresses = NULL;

    if (ev_listener == NULL) {
        LOG(ERROR, "Couldn't create listener: %s", strerror(errno));
        cleanup_and_exit(&ev_base, &ev_listener, &ev_sig, &my_keypair, 8);
    }

    evconnlistener_set_error_cb(ev_listener, accept_error_cb);
    event_base_dispatch(ev_base);

    LOG(NOTICE, "shutdown");
    cleanup_and_exit(&ev_base, &ev_listener, &ev_sig, &my_keypair, 0);
}
