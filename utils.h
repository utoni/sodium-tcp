#ifndef UTILS_H
#define UTILS_H 1

#include <stdlib.h>

#define TIMESTAMP_STRLEN 32

struct cmd_options {
    /* server: private key
     * client: server public key
     */
    char * key_string;
    size_t key_length;
    /* server: listen host
     * client: remote host
     */
    char * host;
    /* server: listen port
     * client: remote port
     */
    char * port;
    /* server: path to write to, received from client via PDU-type DATA
     * client: path to read from, send it via PDU-type DATA
     */
    char * filepath;
};

__attribute__((noreturn)) void usage(const char * const arg0);

void parse_cmdline(struct cmd_options * const opts, int argc, char ** const argv);

char * prettify_bytes_with_units(char * const out, size_t out_size, unsigned long long bytes);

int hostname_to_address(char const * const host, char const * const port, struct addrinfo ** const result);

void strftime_local(double time_in_secs, char * const out, size_t out_size);

#endif
