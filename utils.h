#ifndef UTILS_H
#define UTILS_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    int port;
    /* server: path to write to, received from client via PDU-type DATA
     * client: path to read from, send it via PDU-type DATA
     */
    char * filepath;
};

__attribute__((noreturn)) static inline void usage(const char * const arg0)
{
    fprintf(stderr, "usage: %s -k [SODIUM-KEY] -h [HOST] -p [PORT] -f [FILE]\n", arg0);
    exit(EXIT_FAILURE);
}

static inline void parse_cmdline(struct cmd_options * const opts, int argc, char ** const argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "k:h:p:f:h")) != -1) {
        switch (opt) {
            case 'k':
                opts->key_string = strdup(optarg);
                memset(optarg, '*', strlen(optarg));
                break;
            case 'h':
                opts->host = strdup(optarg);
                break;
            case 'p':
                opts->port = atoi(optarg); /* meh, strtol is king */
                break;
            case 'f':
                opts->filepath = strdup(optarg);
                break;
            default:
                usage(argv[0]);
        }
    }

    if (opts->host == NULL) {
        opts->host = strdup("127.0.0.1");
    }
    if (opts->port == 0) {
        opts->port = 5555;
    }
    if (opts->key_string != NULL) {
        opts->key_length = strlen(opts->key_string);
    }
}

static inline char * prettify_bytes_with_units(char * const out, size_t out_size,
                                               unsigned long long bytes)
{
    static char const * const unit_prefixes[] = {"","Kilo","Mega","Giga","Tera"};
    size_t const unit_prefixes_length = sizeof(unit_prefixes)/sizeof(unit_prefixes[0]);
    unsigned char unit_prefixes_index = 0;
    size_t const convert_bytes_every = 1024;

    while (bytes / convert_bytes_every > 0 && unit_prefixes_index < unit_prefixes_length)
    {
        bytes /= convert_bytes_every;
        unit_prefixes_index++;
    }

    snprintf(out, out_size, "%llu %sBytes", bytes, unit_prefixes[unit_prefixes_index]);

    return out;
}

#endif
