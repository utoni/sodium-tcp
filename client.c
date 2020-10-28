#include <errno.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event-config.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sodium.h>
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

static struct cmd_options opts = {.key_string = NULL, .key_length = 0, .user = NULL, .pass = NULL, .host = NULL, .port = 0, .filepath = NULL};
static int data_fd = -1;

static void send_data(struct connection * const state)
{
    uint8_t buf[WINDOW_SIZE];
    ssize_t bytes_read;

    if (data_fd >= 0) {
        bytes_read = read(data_fd, buf, sizeof(buf));
        if (bytes_read <= 0 || ev_protocol_data(state, buf, (uint32_t)bytes_read) != 0) {
            if (bytes_read == 0) {
                LOG(WARNING, "EoF: Closing file descriptor %d aka %s", data_fd, opts.filepath);
            } else {
                LOG(WARNING, "Closing file descriptor %d aka %s: %s", data_fd, opts.filepath, strerror(errno));
            }
            close(data_fd);
            data_fd = -1;
        } else {
            LOG(NOTICE,
                "Send DATA: %zd bytes, buffer capacity %0.2f%% unused",
                bytes_read,
                100.0f - ((float)bytes_read / sizeof(buf)) * 100.0f);
        }
    }
}

enum recv_return protocol_request_client_auth(struct connection * const state,
                                              struct protocol_header const * const buffer,
                                              size_t * const processed)
{
    (void)state;
    (void)buffer;
    (void)processed;
    return RECV_CALLBACK_NOT_IMPLEMENTED;
}

enum recv_return protocol_request_server_helo(struct connection * const state,
                                              struct protocol_header const * const buffer,
                                              size_t * const processed)
{
    struct protocol_server_helo const * const helo_pkt = (struct protocol_server_helo *)buffer;

    (void)processed;
    LOG(NOTICE, "Server HELLO with message: %.*s", sizeof(helo_pkt->server_message), helo_pkt->server_message);

    if (init_crypto_client(state, helo_pkt->client_rx_header, sizeof(helo_pkt->client_rx_header)) != 0) {
        LOG(ERROR, "Client session keypair generation failed");
        return RECV_FATAL_CALLBACK_ERROR;
    }

    if (ev_setup_generic_timer((struct ev_user_data *)state->user_data, PING_INTERVAL) != 0) {
        LOG(ERROR, "Timer init failed");
        return RECV_FATAL_CALLBACK_ERROR;
    }

    send_data(state);

    state->state = CONNECTION_AUTH_SUCCESS;
    return RECV_SUCCESS;
}

enum recv_return protocol_request_data(struct connection * const state,
                                       struct protocol_header const * const buffer,
                                       size_t * const processed)
{
    struct protocol_data const * const data_pkt = (struct protocol_data *)buffer;

    (void)state;
    (void)processed;
    LOG(LP_DEBUG, "Received DATA with size: %u", data_pkt->header.body_size);
    LOG(NOTICE, "Remote answered: %.*s", (int)data_pkt->header.body_size, data_pkt->payload);
    send_data(state);
    return RECV_SUCCESS;
}

enum recv_return protocol_request_ping(struct connection * const state,
                                       struct protocol_header const * const buffer,
                                       size_t * const processed)
{
    struct protocol_ping const * const ping_pkt = (struct protocol_ping *)buffer;
    char ts_str[TIMESTAMP_STRLEN];
    double ts = to_timestamp(be64toh(ping_pkt->timestamp.sec), ntohl(ping_pkt->timestamp.nsec));

    (void)processed;
    strftime_local(ts, ts_str, sizeof(ts_str));
    LOG(NOTICE, "Received PING with timestamp %.09lfs: %s / %lluns",
        ts, ts_str, extract_nsecs(ts));

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
    char ts_str[TIMESTAMP_STRLEN];
    double ts = to_timestamp(be64toh(pong_pkt->timestamp.sec), ntohl(pong_pkt->timestamp.nsec));

    (void)processed;
    strftime_local(ts, ts_str, sizeof(ts_str));
    LOG(NOTICE, "Received PONG with timestamp %.09lfs: %s / %lluns / %zu outstanding PONG's",
        ts, ts_str, extract_nsecs(ts), state->awaiting_pong);

    if (state->latency > 0.0) {
        LOG(NOTICE, "PING-PONG latency: %.09lfs", state->latency);
    }

    if (state->awaiting_pong > 3) {
        LOG(ERROR, "Waiting for more than 3 PONG's, disconnecting..");
        return RECV_FATAL_CALLBACK_ERROR;
    }

    return RECV_SUCCESS;
}

void on_disconnect(struct connection * const state)
{
    struct ev_user_data * const user_data = (struct ev_user_data *)state->user_data;

    if (user_data != NULL) {
        event_base_loopexit(bufferevent_get_base(user_data->bev), NULL);
    }
}

static void event_cb(struct bufferevent * bev, short events, void * con)
{
    struct connection * const c = (struct connection *)con;
    char events_string[64] = {0};

    ev_events_to_string(events, events_string, sizeof(events_string));
    LOG(LP_DEBUG, "Event(s): 0x%02X (%s)", events, events_string);

    if (events & BEV_EVENT_ERROR) {
        LOG(ERROR, "Error from bufferevent: %s", strerror(errno));
        on_disconnect(c);
        return;
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        LOG(NOTICE, "Remote end closed the connection");
        on_disconnect(c);
        return;
    }
    if (events & BEV_EVENT_CONNECTED) {
        if (c->state != CONNECTION_NEW) {
            LOG(ERROR, "Remote authenticated again?!");
            return;
        }
        LOG(NOTICE, "Connected, sending AUTH");
        if (generate_session_keypair_sodium(c) != 0) {
            LOG(ERROR, "Client session keypair generation failed");
            on_disconnect(c);
            return;
        }
        if (ev_protocol_client_auth(c, opts.user, opts.pass) != 0) {
            LOG(ERROR, "Client AUTH failed");
            on_disconnect(c);
            return;
        }
    }
    if (events & EV_TIMEOUT) {
        LOG(NOTICE, "Timeout");
        bufferevent_enable(bev, EV_READ | EV_WRITE);
        on_disconnect(c);
        return;
    }
}

static void cleanup(struct event_base ** const ev_base,
                    struct event ** const ev_sig,
                    struct longterm_keypair ** const my_keypair)
{
    if (*my_keypair != NULL) {
        sodium_memzero((*my_keypair)->secretkey, crypto_kx_SECRETKEYBYTES);
        free(*my_keypair);
    }
    if (*ev_sig != NULL) {
        event_free(*ev_sig);
    }
    if (*ev_base != NULL) {
        event_base_free(*ev_base);
    }
    *my_keypair = NULL;
    *ev_sig = NULL;
    *ev_base = NULL;
}

__attribute__((noreturn)) static void cleanup_and_exit(struct event_base ** const ev_base,
                                                       struct event ** const ev_sig,
                                                       struct longterm_keypair ** const my_keypair,
                                                       struct connection ** const state,
                                                       int exit_code)
{
    char pretty_bytes_rx[16];
    char pretty_bytes_tx[16];

    LOG(LP_DEBUG, "Cleanup and exit with exit code: %d", exit_code);
    if (*state != NULL) {
        LOG(NOTICE,
            "Closed connection; received %s; sent %s",
            prettify_bytes_with_units(pretty_bytes_rx, sizeof(pretty_bytes_rx), (*state)->total_bytes_recv),
            prettify_bytes_with_units(pretty_bytes_tx, sizeof(pretty_bytes_tx), (*state)->total_bytes_sent));
    }
    *state = NULL;
    cleanup(ev_base, ev_sig, my_keypair);
    exit(exit_code);
}

int main(int argc, char ** argv)
{
    struct addrinfo * connect_addresses = NULL;
    struct addrinfo * ai;
    int gai_errno;
    int bev_connected = 0;
    struct event_base * ev_base = NULL;
    struct event * ev_sig = NULL;
    struct bufferevent * bev;
    struct longterm_keypair * my_keypair = NULL;
    struct connection * c = NULL;
    char ip_str[INET6_ADDRSTRLEN + 1];

    parse_cmdline(&opts, argc, argv);
    if (opts.key_string == NULL) {
        usage(argv[0]);
    }
    if (opts.key_length != crypto_kx_PUBLICKEYBYTES * 2 /* hex string */) {
        LOG(ERROR, "Invalid server public key length: %zu", opts.key_length);
        return 1;
    }
    if (opts.filepath != NULL) {
        data_fd = open(opts.filepath, O_RDONLY, 0);
        if (data_fd < 0) {
            LOG(ERROR, "File '%s' open() error: %s", opts.filepath, strerror(errno));
            return 1;
        }
    }
    if (opts.host == NULL || opts.port == NULL) {
        LOG(ERROR, "Invalid host/port");
        return 2;
    }
    LOG(NOTICE, "Host: %s, Port: %s, User: %s, Pass: %s", opts.host, opts.port, opts.user, opts.pass);
    LOG(NOTICE, "Resolving %s:%s..", opts.host, opts.port);
    gai_errno = hostname_to_address(opts.host, opts.port, &connect_addresses);
    if (gai_errno != 0) {
        LOG(ERROR, "Address/Service translation error for %s:%s: %s", opts.host, opts.port, gai_strerror(gai_errno));
        return 2;
    }

    double ts = create_timestamp();
    uint64_t ts_seed = (uint64_t)ts + extract_nsecs(ts);
    srandom(ts_seed);

    if (sodium_init() != 0) {
        LOG(ERROR, "Sodium init failed");
        return 3;
    }

    /* generate client keypair */
    my_keypair = generate_keypair_sodium();
    if (my_keypair == NULL) {
        LOG(ERROR, "Sodium keypair generation failed");
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 5);
    }
    log_bin2hex_sodium(NOTICE, "Client public key", my_keypair->publickey, sizeof(my_keypair->publickey));

    /* create global connection state */
    c = new_connection_to_server(my_keypair);
    if (c == NULL) {
        LOG(ERROR, "Could not create connection state");
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 6);
    }

    /* parse server public key into global connection state */
    if (sodium_hex2bin(
            c->peer_publickey, sizeof(c->peer_publickey), opts.key_string, opts.key_length, NULL, NULL, NULL) != 0) {
        LOG(ERROR, "Could not parse server public key: %s", opts.key_string);
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 7);
    }
    log_bin2hex_sodium(NOTICE, "Server public key", c->peer_publickey, sizeof(c->peer_publickey));

    ev_base = event_base_new();
    if (ev_base == NULL) {
        LOG(ERROR, "Couldn't open event base");
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 8);
    }

    ev_sig = evsignal_new(ev_base, SIGINT, ev_sighandler, event_self_cbarg());
    if (ev_sig == NULL) {
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 9);
    }
    if (event_add(ev_sig, NULL) != 0) {
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 10);
    }

    bev =
        bufferevent_socket_new(ev_base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
    if (bev == NULL) {
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 11);
    }

    if (ev_setup_user_data(bev, c) != 0) {
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 12);
    }

    bufferevent_setcb(bev, ev_read_cb, ev_write_cb, event_cb, c);
    if (bufferevent_enable(bev, EV_READ | EV_WRITE) != 0) {
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 13);
    }
    ev_set_io_timeouts(bev);

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
                cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 14);
        }
        if (inet_ntop(ai->ai_family, sa, ip_str, sl) == NULL) {
            LOG(WARNING, "Invalid IPv4 host");
            continue;
        }

        LOG(NOTICE, "Connecting to %s:%s", ip_str, opts.port);
        if (bufferevent_socket_connect(bev, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            bev_connected = 1;
            break;
        }
    }
    freeaddrinfo(connect_addresses);
    connect_addresses = NULL;

    if (bev_connected == 0) {
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 14);
    }

    LOG(LP_DEBUG, "Event loop");
    if (event_base_dispatch(ev_base) != 0) {
        cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 15);
    }

    cleanup_and_exit(&ev_base, &ev_sig, &my_keypair, &c, 0);
}
