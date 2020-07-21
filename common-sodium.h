#ifndef COMMON_SODIUM_H
#define COMMON_SODIUM_H 1

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>

#include "logging.h"

struct connection;

void log_bin2hex_sodium(enum log_priority log_prio, char const * const prefix, uint8_t const * const buffer, size_t size);

__attribute__((warn_unused_result)) struct longterm_keypair * generate_keypair_sodium(void);

__attribute__((warn_unused_result)) struct longterm_keypair * generate_keypair_from_secretkey_hexstr_sodium(
    char const * const secretkey_hexstr, size_t secretkey_hexstr_len);

__attribute__((warn_unused_result)) int generate_session_keypair_sodium(struct connection * const state);

__attribute__((warn_unused_result)) int init_crypto_server(struct connection * const state,
                                                           unsigned char const * const server_rx_header,
                                                           size_t server_rx_header_size);

__attribute__((warn_unused_result)) int init_crypto_client(struct connection * const state,
                                                           unsigned char const * const client_rx_header,
                                                           size_t client_rx_header_size);

#endif
