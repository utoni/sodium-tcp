#include <time.h>
#include <sys/time.h>

#include "protocol.h"

#define PLAIN_PACKET_POINTER_AFTER_HEADER(pointer) ((uint8_t *)pointer + PLAIN_PACKET_HEADER_SIZE)
#define CRYPT_PACKET_POINTER_AFTER_HEADER(pointer) ((uint8_t *)pointer + CRYPT_PACKET_HEADER_SIZE)

#define PLAIN_PACKET_HEADER_BODY_SIZE(header) (header->body_size)
#define CRYPT_PACKET_HEADER_BODY_SIZE(header) (PLAIN_PACKET_HEADER_BODY_SIZE(header) + CRYPTO_BYTES_POSTAUTH)

/*****************************
 * PDU receive functionality *
 *****************************/

struct readonly_buffer {
    uint8_t const * const pointer;
    size_t const size;
};

struct readwrite_buffer {
    uint8_t * const pointer;
    size_t const size;
    size_t used;
};

typedef enum recv_return (*protocol_cb)(struct connection * const state,
                                        struct protocol_header const * const buffer,
                                        size_t * const processed);

const struct protocol_callback {
    protocol_cb callback;
} protocol_callbacks[] = {[TYPE_INVALID] = {NULL},
                          [TYPE_CLIENT_AUTH] = {protocol_request_client_auth},
                          [TYPE_SERVER_HELO] = {protocol_request_server_helo},
                          [TYPE_DATA] = {protocol_request_data},
                          [TYPE_PING] = {protocol_request_ping},
                          [TYPE_PONG] = {protocol_request_pong},
                          [TYPE_COUNT] = {NULL}};

static size_t calculate_min_recv_size(enum header_types type, size_t size)
{
    switch (type) {
        case TYPE_CLIENT_AUTH:
            if (size != sizeof(struct protocol_client_auth) - sizeof(struct protocol_header)) {
                return 0;
            }
            return sizeof(struct protocol_client_auth);
        case TYPE_SERVER_HELO:
            if (size != sizeof(struct protocol_server_helo) - sizeof(struct protocol_header)) {
                return 0;
            }
            return sizeof(struct protocol_server_helo);
        case TYPE_DATA:
            return sizeof(struct protocol_data);
        case TYPE_PING:
            return sizeof(struct protocol_ping);
        case TYPE_PONG:
            return sizeof(struct protocol_pong);

        /* required to not generate compiler warnings */
        case TYPE_COUNT:
        case TYPE_INVALID:
            break;
    }

    return 0;
}

static enum recv_return parse_protocol_timestamp(char const protocol_timestamp[PROTOCOL_TIME_STRLEN],
                                                 struct tm * const dest)
{
    char timestamp_sz[PROTOCOL_TIME_STRLEN + 1];
    strncpy(timestamp_sz, protocol_timestamp, sizeof(timestamp_sz) - 1);
    timestamp_sz[PROTOCOL_TIME_STRLEN] = '\0';
    strptime(timestamp_sz, "%a, %d %b %Y %T %z", dest);
    return RECV_SUCCESS;
}

static enum recv_return process_body(struct connection * const state,
                                     struct readonly_buffer const * const encrypted,
                                     struct readwrite_buffer * const decrypted,
                                     size_t * const processed)
{
    struct protocol_header const * const hdr = (struct protocol_header *)decrypted->pointer;
    enum recv_return retval;

    (void)encrypted;
    switch (hdr->pdu_type) {
        case TYPE_CLIENT_AUTH: {
            struct protocol_client_auth const * const auth_pkt = (struct protocol_client_auth *)hdr;

            /* client greets us, protocol version check */
            state->used_protocol_version = ntohl(auth_pkt->protocol_version);
            if (state->used_protocol_version != PROTOCOL_VERSION) {
                return RECV_FATAL;
            }
            memcpy(state->last_nonce, auth_pkt->nonce, crypto_box_NONCEBYTES);
            memcpy(state->peer_publickey, auth_pkt->client_publickey, crypto_kx_PUBLICKEYBYTES);
            *processed += CRYPT_PACKET_SIZE_CLIENT_AUTH;
            break;
        }
        case TYPE_SERVER_HELO: {
            struct protocol_server_helo const * const helo_pkt = (struct protocol_server_helo *)hdr;

            /* server greets us, increment and validate nonce */
            sodium_increment(state->last_nonce, crypto_box_NONCEBYTES);
            if (sodium_memcmp(helo_pkt->nonce_increment, state->last_nonce, crypto_box_NONCEBYTES) != 0) {
                return RECV_FATAL;
            }
            *processed += CRYPT_PACKET_SIZE_SERVER_HELO;
            break;
        }
        case TYPE_DATA: {
            *processed += CRYPT_PACKET_SIZE_DATA + PLAIN_PACKET_HEADER_BODY_SIZE(hdr);
            break;
        }
        case TYPE_PING: {
            struct protocol_ping const * const ping_pkt = (struct protocol_ping *)hdr;

            retval = parse_protocol_timestamp(ping_pkt->timestamp, &state->last_ping_recv);
            if (retval != RECV_SUCCESS) {
                return retval;
            }
            state->last_ping_recv_usec = be64toh(ping_pkt->timestamp_usec);
            *processed += CRYPT_PACKET_SIZE_PING;
            break;
        }
        case TYPE_PONG: {
            struct protocol_pong const * const pong_pkt = (struct protocol_pong *)hdr;

            retval = parse_protocol_timestamp(pong_pkt->timestamp, &state->last_pong_recv);
            if (retval != RECV_SUCCESS) {
                return retval;
            }
            if (state->awaiting_pong == 0) {
                return RECV_FATAL;
            }
            state->awaiting_pong--;
            state->last_pong_recv_usec = be64toh(pong_pkt->timestamp_usec);
            state->latency_usec = state->last_pong_recv_usec - state->last_ping_send_usec;
            *processed += CRYPT_PACKET_SIZE_PONG;
            break;
        }
        /* required to not generate compiler warnings */
        case TYPE_COUNT:
        case TYPE_INVALID:
            return RECV_FATAL;
    }

    return RECV_SUCCESS;
}

static enum recv_return run_protocol_callback(struct connection * const state,
                                              struct readonly_buffer const * const encrypted,
                                              struct readwrite_buffer * const decrypted,
                                              size_t * const processed)
{
    struct protocol_header const * const hdr = (struct protocol_header *)decrypted->pointer;
    enum header_types type = (enum header_types)hdr->pdu_type;
    size_t min_size = 0;
    uint32_t size = hdr->body_size;

    switch (state->state) {
        case CONNECTION_INVALID:
            return RECV_FATAL;
        case CONNECTION_NEW:
            /* only TYPE_CLIENT_AUTH and TYPE_SERVER_HELO allowed if CONNECTION_NEW */
            if (type != TYPE_CLIENT_AUTH && type != TYPE_SERVER_HELO) {
                return RECV_FATAL_UNAUTH;
            } else {
                break;
            }
        case CONNECTION_AUTH_SUCCESS:
            break;
    }

    min_size = calculate_min_recv_size(type, size);
    if (min_size == 0) {
        return RECV_CORRUPT_PACKET;
    }

    if (decrypted->used < min_size) {
        return RECV_BUFFER_NEED_MORE_DATA;
    }

    if (protocol_callbacks[type].callback == NULL) {
        return RECV_CALLBACK_NOT_IMPLEMENTED;
    }

    if (process_body(state, encrypted, decrypted, processed) != RECV_SUCCESS) {
        return RECV_FATAL;
    }

    return protocol_callbacks[type].callback(state, hdr, processed);
}

static void header_ntoh(struct protocol_header * const hdr)
{
    hdr->magic = ntohl(hdr->magic);
    hdr->pdu_type = ntohs(hdr->pdu_type);
    hdr->body_size = ntohl(hdr->body_size);
}

static enum recv_return validate_header(struct protocol_header const * const hdr, size_t buffer_size)
{
    enum header_types type = (enum header_types)hdr->pdu_type;
    uint32_t size;

    if (hdr->magic != PROTOCOL_MAGIC) {
        return RECV_CORRUPT_PACKET;
    }

    size = hdr->body_size;
    if (size > WINDOW_SIZE) {
        return RECV_FATAL_REMOTE_WINDOW_SIZE;
    }
    if (size > buffer_size) {
        return RECV_BUFFER_NEED_MORE_DATA;
    }

    if (type <= TYPE_INVALID || type >= TYPE_COUNT) {
        return RECV_CORRUPT_PACKET;
    }

    return RECV_SUCCESS;
}

static enum recv_return decrypt_preauth(struct connection * const state,
                                        struct readonly_buffer const * const encrypted,
                                        struct readwrite_buffer * const decrypted)
{
    enum recv_return retval;
    struct protocol_header * hdr;
    size_t crypted_size;

    if (state->is_server_side == 1) {
        crypted_size = CRYPT_PACKET_SIZE_CLIENT_AUTH;
    } else {
        crypted_size = CRYPT_PACKET_SIZE_SERVER_HELO;
    }

    if (encrypted->size < crypted_size) {
        return RECV_BUFFER_NEED_MORE_DATA;
    }
    if (decrypted->used + (crypted_size - CRYPTO_BYTES_PREAUTH) > decrypted->size) {
        return RECV_FATAL;
    }

    if (crypto_box_seal_open(decrypted->pointer,
                             encrypted->pointer,
                             crypted_size,
                             state->my_keypair->publickey,
                             state->my_keypair->secretkey) != 0) {

        return RECV_FATAL_CRYPTO_ERROR;
    }
    decrypted->used += (crypted_size - CRYPTO_BYTES_PREAUTH);

    hdr = (struct protocol_header *)decrypted->pointer;
    header_ntoh(hdr);

    retval = validate_header(hdr, decrypted->used);
    if (retval != RECV_SUCCESS) {
        return retval;
    }

    return RECV_SUCCESS;
}

static enum recv_return decrypt_header(struct connection * const state,
                                       struct readonly_buffer const * const encrypted,
                                       struct readwrite_buffer * const decrypted)
{
    unsigned char tag = 0;

    if (encrypted->size < CRYPT_PACKET_HEADER_SIZE) {
        return RECV_BUFFER_NEED_MORE_DATA;
    }
    if (decrypted->used + PLAIN_PACKET_HEADER_SIZE > decrypted->size) {
        return RECV_FATAL;
    }

    if (state->partial_packet_received == 0 && crypto_secretstream_xchacha20poly1305_pull(&state->crypto_rx_state,
                                                                                          decrypted->pointer,
                                                                                          NULL,
                                                                                          &tag,
                                                                                          encrypted->pointer,
                                                                                          CRYPT_PACKET_HEADER_SIZE,
                                                                                          NULL,
                                                                                          0) != 0) {
        return RECV_FATAL_CRYPTO_ERROR;
    }

    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        return RECV_FATAL;
    }

    decrypted->used += PLAIN_PACKET_HEADER_SIZE;
    return RECV_SUCCESS;
}

static enum recv_return decrypt_body(struct connection * const state,
                                     struct protocol_header const * const hdr,
                                     struct readonly_buffer const * const encrypted,
                                     struct readwrite_buffer * const decrypted)
{
    unsigned char tag = 0;

    if (encrypted->size < CRYPT_PACKET_HEADER_BODY_SIZE(hdr) + CRYPT_PACKET_HEADER_SIZE) {
        return RECV_BUFFER_NEED_MORE_DATA;
    }
    if (decrypted->used + PLAIN_PACKET_HEADER_BODY_SIZE(hdr) > decrypted->size) {
        return RECV_FATAL;
    }

    if (crypto_secretstream_xchacha20poly1305_pull(&state->crypto_rx_state,
                                                   PLAIN_PACKET_POINTER_AFTER_HEADER(decrypted->pointer),
                                                   NULL,
                                                   &tag,
                                                   CRYPT_PACKET_POINTER_AFTER_HEADER(encrypted->pointer),
                                                   CRYPT_PACKET_HEADER_BODY_SIZE(hdr),
                                                   NULL,
                                                   0) != 0) {
        return RECV_FATAL_CRYPTO_ERROR;
    }

    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        return RECV_FATAL;
    }

    decrypted->used += PLAIN_PACKET_HEADER_BODY_SIZE(hdr);
    return RECV_SUCCESS;
}

static enum recv_return decrypt_postauth(struct connection * const state,
                                         struct readonly_buffer const * const encrypted,
                                         struct readwrite_buffer * const decrypted)
{
    enum recv_return retval;
    struct protocol_header * hdr;

    retval = decrypt_header(state, encrypted, decrypted);
    if (retval != RECV_SUCCESS) {
        return retval;
    }

    hdr = (struct protocol_header *)decrypted->pointer;
    if (state->partial_packet_received != 0) {
        *hdr = state->partial_packet_header;
    } else {
        header_ntoh(hdr);
    }

    retval = validate_header(hdr, decrypted->used);
    if (retval != RECV_SUCCESS && retval != RECV_BUFFER_NEED_MORE_DATA) {
        return retval;
    }

    retval = decrypt_body(state, hdr, encrypted, decrypted);
    if (retval != RECV_SUCCESS) {
        return retval;
    }

    return RECV_SUCCESS;
}

enum recv_return process_received(struct connection * const state,
                                  uint8_t const * const buffer,
                                  size_t * const buffer_size)
{
    uint8_t decrypted_buffer[PLAIN_PACKET_HEADER_SIZE + WINDOW_SIZE];
    struct readonly_buffer const encrypted = {.pointer = buffer, .size = *buffer_size};
    struct readwrite_buffer decrypted = {.pointer = &decrypted_buffer[0], .size = sizeof(decrypted_buffer), .used = 0};

    switch (state->state) {
        case CONNECTION_INVALID:
            return RECV_FATAL;
        case CONNECTION_NEW: {
            enum recv_return retval = decrypt_preauth(state, &encrypted, &decrypted);
            if (retval != RECV_SUCCESS) {
                return retval;
            }
            break;
        }
        case CONNECTION_AUTH_SUCCESS: {
            enum recv_return retval = decrypt_postauth(state, &encrypted, &decrypted);
            if (retval != RECV_SUCCESS) {
                if (retval == RECV_BUFFER_NEED_MORE_DATA) {
                    if (decrypted.used == PLAIN_PACKET_HEADER_SIZE) {
                        state->partial_packet_received = 1;
                        state->partial_packet_header = *(struct protocol_header *)decrypted_buffer;
                    } else if (decrypted.used != 0) {
                        return RECV_CORRUPT_PACKET;
                    }
                }
                return retval;
            }
            break;
        }
    }

    state->total_bytes_recv += *buffer_size;
    state->partial_packet_received = 0;
    *buffer_size = 0;
    return run_protocol_callback(state, &encrypted, &decrypted, buffer_size);
}

/**************************
 * PDU send functionality *
 **************************/

static void protocol_response(struct connection * const state,
                              void * const buffer, uint32_t body_and_payload_size,
                              enum header_types type)
{
    struct protocol_header * const header = (struct protocol_header *)buffer;

    header->magic = htonl(PROTOCOL_MAGIC);
    header->pdu_type = htons((uint16_t)type);
    header->body_size = htonl(body_and_payload_size - sizeof(*header));

    state->total_bytes_sent += (sizeof(*header) + body_and_payload_size);
}

void protocol_response_client_auth(unsigned char out[CRYPT_PACKET_SIZE_CLIENT_AUTH],
                                   struct connection * const state,
                                   const char * const user,
                                   const char * const pass)
{
    struct protocol_client_auth auth_pkt;

    protocol_response(state, &auth_pkt, sizeof(auth_pkt), TYPE_CLIENT_AUTH);
    /* version */
    state->used_protocol_version = PROTOCOL_VERSION;
    auth_pkt.protocol_version = htonl(state->used_protocol_version);
    /* nonce */
    randombytes_buf(state->last_nonce, crypto_box_NONCEBYTES);
    memcpy(auth_pkt.nonce, state->last_nonce, crypto_box_NONCEBYTES);
    /* keys required by server */
    memcpy(auth_pkt.client_publickey, state->my_keypair->publickey, crypto_kx_PUBLICKEYBYTES);
    /* login credentials */
    randombytes_buf(&auth_pkt.login, sizeof(auth_pkt.login));
    randombytes_buf(&auth_pkt.passphrase, sizeof(auth_pkt.passphrase));
    strncpy(auth_pkt.login, user, sizeof(auth_pkt.login));
    strncpy(auth_pkt.passphrase, pass, sizeof(auth_pkt.passphrase));
    /* setup secretstream header for server_rx */
    crypto_secretstream_xchacha20poly1305_init_push(&state->crypto_tx_state,
                                                    auth_pkt.server_rx_header,
                                                    state->session_keys->tx);
    /* encrypt */
    crypto_box_seal(out, (uint8_t *)&auth_pkt, sizeof(auth_pkt), state->peer_publickey);
}

void protocol_response_server_helo(unsigned char out[CRYPT_PACKET_SIZE_SERVER_HELO],
                                   struct connection * const state,
                                   const char * const welcome_message)
{
    struct protocol_server_helo helo_pkt;

    protocol_response(state, &helo_pkt, sizeof(helo_pkt), TYPE_SERVER_HELO);
    /* nonce */
    sodium_increment(state->last_nonce, crypto_box_NONCEBYTES);
    memcpy(helo_pkt.nonce_increment, state->last_nonce, crypto_box_NONCEBYTES);
    /* server messgae */
    strncpy(helo_pkt.server_message, welcome_message, sizeof(helo_pkt.server_message));
    /* setup secretstream header for client_rx */
    crypto_secretstream_xchacha20poly1305_init_push(&state->crypto_tx_state,
                                                    helo_pkt.client_rx_header,
                                                    state->session_keys->tx);
    /* encrypt */
    crypto_box_seal(out, (uint8_t *)&helo_pkt, sizeof(helo_pkt), state->peer_publickey);
}

void protocol_response_data(uint8_t * out,
                            size_t const out_size,
                            struct connection * const state,
                            uint8_t const * const payload,
                            size_t payload_size)
{
    struct protocol_header data_hdr;

    if (out_size != CRYPT_PACKET_SIZE_DATA + payload_size) {
        return;
    }
    protocol_response(state, &data_hdr, sizeof(data_hdr) + payload_size, TYPE_DATA);

    crypto_secretstream_xchacha20poly1305_push(
        &state->crypto_tx_state, out, NULL, (uint8_t *)&data_hdr, sizeof(data_hdr), NULL, 0, 0);
    crypto_secretstream_xchacha20poly1305_push(
        &state->crypto_tx_state, CRYPT_PACKET_POINTER_AFTER_HEADER(out), NULL, payload, payload_size, NULL, 0, 0);
}

static int create_timestamp(struct tm * const timestamp,
                            char timestamp_str[PROTOCOL_TIME_STRLEN],
                            suseconds_t * const usec)
{
    time_t ts;
    struct timeval ts_val;

    gettimeofday(&ts_val, NULL);
    *usec = ts_val.tv_usec;
    ts = time(NULL);
    gmtime_r(&ts, timestamp);

    if (timestamp_str) {
        return strftime(timestamp_str, PROTOCOL_TIME_STRLEN, "%a, %d %b %Y %T %z", timestamp);
    }
    return 0;
}

void protocol_response_ping(unsigned char out[CRYPT_PACKET_SIZE_PING], struct connection * const state)
{
    struct protocol_ping ping_pkt;

    state->awaiting_pong++;
    protocol_response(state, &ping_pkt, sizeof(ping_pkt), TYPE_PING);
    create_timestamp(&state->last_ping_send, ping_pkt.timestamp, &state->last_ping_send_usec);
    ping_pkt.timestamp_usec = htobe64(state->last_ping_send_usec);

    crypto_secretstream_xchacha20poly1305_push(
        &state->crypto_tx_state, &out[0], NULL, (uint8_t *)&ping_pkt.header, sizeof(ping_pkt.header), NULL, 0, 0);
    crypto_secretstream_xchacha20poly1305_push(&state->crypto_tx_state,
                                               CRYPT_PACKET_POINTER_AFTER_HEADER(&out[0]),
                                               NULL,
                                               (uint8_t *)&ping_pkt.header + PLAIN_PACKET_HEADER_SIZE,
                                               PLAIN_PACKET_BODY_SIZE(struct protocol_ping),
                                               NULL,
                                               0,
                                               0);
}

void protocol_response_pong(unsigned char out[CRYPT_PACKET_SIZE_PONG], struct connection * const state)
{
    struct protocol_pong pong_pkt;

    protocol_response(state, &pong_pkt, sizeof(pong_pkt), TYPE_PONG);
    create_timestamp(&state->last_pong_send, pong_pkt.timestamp, &state->last_pong_send_usec);
    pong_pkt.timestamp_usec = htobe64(state->last_pong_send_usec);

    crypto_secretstream_xchacha20poly1305_push(
        &state->crypto_tx_state, &out[0], NULL, (uint8_t *)&pong_pkt.header, sizeof(pong_pkt.header), NULL, 0, 0);
    crypto_secretstream_xchacha20poly1305_push(&state->crypto_tx_state,
                                               CRYPT_PACKET_POINTER_AFTER_HEADER(&out[0]),
                                               NULL,
                                               (uint8_t *)&pong_pkt.header + PLAIN_PACKET_HEADER_SIZE,
                                               PLAIN_PACKET_BODY_SIZE(struct protocol_pong),
                                               NULL,
                                               0,
                                               0);
}

/**********************************
 * connection state functionality *
 **********************************/

static struct connection * new_connection(struct longterm_keypair const * const my_keypair)
{
    struct connection * c = (struct connection *)malloc(sizeof(*c));

    if (c == NULL) {
        return NULL;
    }
    c->state = CONNECTION_NEW;
    c->awaiting_pong = 0;
    c->session_keys = NULL;
    c->my_keypair = my_keypair;
    c->user_data = NULL;
    create_timestamp(&c->last_ping_recv, NULL, &c->last_ping_recv_usec);
    create_timestamp(&c->last_ping_send, NULL, &c->last_ping_send_usec);
    create_timestamp(&c->last_pong_recv, NULL, &c->last_pong_recv_usec);
    create_timestamp(&c->last_pong_send, NULL, &c->last_pong_send_usec);
    c->latency_usec = 0.0;
    c->total_bytes_recv = 0;
    c->total_bytes_sent = 0;
    sodium_mlock(c, sizeof(*c));

    return c;
}

struct connection * new_connection_from_client(struct longterm_keypair const * const my_keypair)
{
    struct connection * c = new_connection(my_keypair);

    if (c == NULL) {
        return NULL;
    }
    c->is_server_side = 1;

    return c;
}

struct connection * new_connection_to_server(struct longterm_keypair const * const my_keypair)
{
    struct connection * c = new_connection(my_keypair);

    if (c == NULL) {
        return NULL;
    }
    c->is_server_side = 0;

    return c;
}
