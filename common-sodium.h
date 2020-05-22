#ifndef COMMON_SODIUM_H
#define COMMON_SODIUM_H 1

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>

struct connection;

void log_bin2hex_sodium(char const * const prefix, uint8_t const * const buffer, size_t size);

__attribute__((warn_unused_result)) struct longterm_keypair * generate_keypair_sodium(void);

__attribute__((warn_unused_result)) struct longterm_keypair * generate_keypair_from_secretkey_hexstr_sodium(
    char const * const secretkey_hexstr, size_t secretkey_hexstr_len);

__attribute__((warn_unused_result)) int generate_session_keypair_sodium(struct connection * const state);

__attribute__((warn_unused_result)) int init_sockaddr_inet(struct sockaddr_in * const sin,
                                                           const char * const host,
                                                           int port,
                                                           char ip_str[INET6_ADDRSTRLEN + 1]);

#endif
