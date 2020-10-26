#ifndef PROTOCOL_H
#define PROTOCOL_H 1

#include <arpa/inet.h>
#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define PROTOCOL_ATTRIBUTES __attribute__((packed))
#define PROTOCOL_MAGIC 0xBAADC0DE
#define PROTOCOL_VERSION 0xDEADCAFE
#define WINDOW_SIZE (65535 * 2)
#if WINDOW_SIZE > (UINT_MAX)
#error "Window size is limited by sizeof(header.body_size)"
#endif

#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))

#define CRYPTO_BYTES_PREAUTH crypto_box_SEALBYTES
#define CRYPTO_BYTES_POSTAUTH crypto_secretstream_xchacha20poly1305_ABYTES
#define PLAIN_PACKET_HEADER_SIZE ((size_t)sizeof(struct protocol_header))
#define CRYPT_PACKET_HEADER_SIZE (PLAIN_PACKET_HEADER_SIZE + CRYPTO_BYTES_POSTAUTH)

#define PLAIN_PACKET_BODY_SIZE(protocol_type) ((size_t)(sizeof(protocol_type) - PLAIN_PACKET_HEADER_SIZE))
#define CRYPT_PACKET_BODY_SIZE(protocol_type) ((size_t)(PLAIN_PACKET_BODY_SIZE(protocol_type) + CRYPTO_BYTES_POSTAUTH))

#define PLAIN_PACKET_SIZE_TOTAL(protocol_type)                                                                         \
    ((size_t)(PLAIN_PACKET_HEADER_SIZE + PLAIN_PACKET_BODY_SIZE(protocol_type)))
#define CRYPT_PACKET_SIZE_TOTAL(protocol_type)                                                                         \
    ((size_t)(CRYPT_PACKET_HEADER_SIZE + CRYPT_PACKET_BODY_SIZE(protocol_type)))

#define CRYPT_PACKET_SIZE_CLIENT_AUTH                                                                                  \
    ((size_t)(CRYPTO_BYTES_PREAUTH + PLAIN_PACKET_SIZE_TOTAL(struct protocol_client_auth)))
#define CRYPT_PACKET_SIZE_SERVER_HELO                                                                                  \
    ((size_t)(CRYPTO_BYTES_PREAUTH + PLAIN_PACKET_SIZE_TOTAL(struct protocol_server_helo)))
/* special-case: CRYPT_PACKET_SIZE_DATA is a dynamic sized packet */
#define CRYPT_PACKET_SIZE_DATA CRYPT_PACKET_SIZE_TOTAL(struct protocol_data)
#define CRYPT_PACKET_SIZE_PING CRYPT_PACKET_SIZE_TOTAL(struct protocol_ping)
#define CRYPT_PACKET_SIZE_PONG CRYPT_PACKET_SIZE_TOTAL(struct protocol_pong)

enum header_types {
    TYPE_INVALID = 0,

    TYPE_CLIENT_AUTH,
    TYPE_SERVER_HELO,
    TYPE_DATA,
    TYPE_PING,
    TYPE_PONG,

    TYPE_COUNT
};

struct protocol_header {
    uint32_t magic;
    uint32_t pdu_type;
    uint32_t body_size;
} PROTOCOL_ATTRIBUTES;

struct protocol_client_auth {
    struct protocol_header header;
    uint32_t protocol_version;
    uint8_t nonce[crypto_box_NONCEBYTES];
    unsigned char server_rx_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    /*
     * REMEMBER that sending the public key alone without any shared secret (e.g. user/pass)
     * makes your application vulnerable to Man-In-The-Middle if an attacker knows the server's public key.
     * However the auth packet must be encrypted using the servers public key to
     * prevent tampering of the client publickey and of course a login and passphrase
     * should never be sent in plaintext over an insecure network.
     */
    uint8_t client_publickey[crypto_kx_PUBLICKEYBYTES];
    char login[128];
    char passphrase[128]; /* passphase is not hashed, so authentication APIs like PAM can still used */
} PROTOCOL_ATTRIBUTES;

struct protocol_server_helo {
    struct protocol_header header;
    uint8_t nonce_increment[crypto_box_NONCEBYTES];
    unsigned char client_rx_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    char server_message[128];
} PROTOCOL_ATTRIBUTES;

struct protocol_data {
    struct protocol_header header;
    /* pointer to the dynamic sized packet payload with size header.body_size */
    uint8_t payload[0];
} PROTOCOL_ATTRIBUTES;

struct protocol_ping {
    struct protocol_header header;
    struct {
        uint64_t sec;
        uint32_t nsec;
    } timestamp;
} PROTOCOL_ATTRIBUTES;

struct protocol_pong {
    struct protocol_header header;
    struct {
        uint64_t sec;
        uint32_t nsec;
    } timestamp;
} PROTOCOL_ATTRIBUTES;

enum state { CONNECTION_INVALID = 0, CONNECTION_NEW, CONNECTION_AUTH_SUCCESS };

struct longterm_keypair {
    uint8_t publickey[crypto_kx_PUBLICKEYBYTES];
    uint8_t secretkey[crypto_kx_SECRETKEYBYTES];
};

struct session_keys {
    uint8_t rx[crypto_kx_SESSIONKEYBYTES]; /* key required to read data from remote `pull' */
    uint8_t tx[crypto_kx_SESSIONKEYBYTES]; /* key required to send data to remote `push' */
};

struct connection {
    enum state state;
    int is_server_side;
    size_t awaiting_pong;
    uint32_t used_protocol_version;
    /* header received and decrypted, but not yet enough data for body received */
    int partial_packet_received;
    /* decrypted header form a partial received PDU */
    struct protocol_header partial_packet_header;

    /* state required when reading data from remote aka `pull' */
    crypto_secretstream_xchacha20poly1305_state crypto_rx_state;
    /* state required when sending data to remote aka `push' */
    crypto_secretstream_xchacha20poly1305_state crypto_tx_state;

    /* nonce must be incremented before sending or comparing a remote received one */
    uint8_t last_nonce[crypto_box_NONCEBYTES];

    double last_ping_recv_remote;
    double last_pong_recv_remote;

    double last_ping_send;
    double last_ping_recv;
    double last_pong_send;
    double last_pong_recv;
    double latency;

    uint64_t total_bytes_recv;
    uint64_t total_bytes_sent;

    /* generated symmetric session keys used by server and client */
    struct session_keys * session_keys;

    /* used by server and client to store the respective peer public key */
    uint8_t peer_publickey[crypto_kx_PUBLICKEYBYTES];
    struct longterm_keypair const * my_keypair;

    /* reserved for the underlying network io system e.g. libevent */
    void * user_data;
};

enum recv_return {
    RECV_SUCCESS,
    RECV_FATAL,
    RECV_FATAL_UNAUTH,
    RECV_FATAL_CRYPTO_ERROR,
    RECV_FATAL_REMOTE_WINDOW_SIZE,
    RECV_FATAL_CALLBACK_ERROR,
    RECV_CORRUPT_PACKET,
    RECV_BUFFER_NEED_MORE_DATA,
    RECV_CALLBACK_NOT_IMPLEMENTED
};

/*****************************
 * PDU receive functionality *
 *****************************/

enum recv_return WARN_UNUSED_RESULT process_received(struct connection * const state,
                                                     uint8_t const * const buffer,
                                                     size_t * const buffer_size);

/* The following functions have to be implemented in your application e.g. client/server. */

extern enum recv_return WARN_UNUSED_RESULT protocol_request_client_auth(struct connection * const state,
                                                                        struct protocol_header const * const buffer,
                                                                        size_t * const processed);
extern enum recv_return WARN_UNUSED_RESULT protocol_request_server_helo(struct connection * const,
                                                                        struct protocol_header const * const buffer,
                                                                        size_t * const processed);
extern enum recv_return WARN_UNUSED_RESULT protocol_request_data(struct connection * const state,
                                                                 struct protocol_header const * const buffer,
                                                                 size_t * const processed);
extern enum recv_return WARN_UNUSED_RESULT protocol_request_ping(struct connection * const state,
                                                                 struct protocol_header const * const buffer,
                                                                 size_t * const processed);
extern enum recv_return WARN_UNUSED_RESULT protocol_request_pong(struct connection * const state,
                                                                 struct protocol_header const * const buffer,
                                                                 size_t * const processed);

/**************************
 * PDU send functionality *
 **************************/

void protocol_response_client_auth(unsigned char out[CRYPT_PACKET_SIZE_CLIENT_AUTH],
                                   struct connection * const state,
                                   const char * const user,
                                   const char * const pass);
void protocol_response_server_helo(unsigned char out[CRYPT_PACKET_SIZE_SERVER_HELO],
                                   struct connection * const state,
                                   const char * const welcome_message);
void protocol_response_data(uint8_t * const out,
                            size_t out_size,
                            struct connection * const state,
                            uint8_t const * const payload,
                            size_t payload_size);
void protocol_response_ping(unsigned char out[CRYPT_PACKET_SIZE_PING], struct connection * const state);
void protocol_response_pong(unsigned char out[CRYPT_PACKET_SIZE_PONG], struct connection * const state);

/**********************************
 * connection state functionality *
 **********************************/

struct connection * WARN_UNUSED_RESULT new_connection_from_client(struct longterm_keypair const * const my_keypair);
struct connection * WARN_UNUSED_RESULT new_connection_to_server(struct longterm_keypair const * const my_keypair);

/***********************
 * timestamp functions *
 ***********************/
double WARN_UNUSED_RESULT create_timestamp(void);
double WARN_UNUSED_RESULT to_timestamp(uint64_t time_in_secs, uint32_t nano_secs);
uint32_t WARN_UNUSED_RESULT extract_nsecs(double time_in_secs);

#endif
