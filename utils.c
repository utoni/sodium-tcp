#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

__attribute__((noreturn)) void usage(const char * const arg0)
{
    fprintf(stderr, "usage: %s -k [SODIUM-KEY] -h [HOST] -p [PORT] -f [FILE]\n", arg0);
    exit(EXIT_FAILURE);
}

void parse_cmdline(struct cmd_options * const opts, int argc, char ** const argv)
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
                opts->port = strdup(optarg);
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
    if (opts->port == NULL) {
        opts->port = strdup("5555");
    }
    if (opts->key_string != NULL) {
        opts->key_length = strlen(opts->key_string);
    }
}

char * prettify_bytes_with_units(char * const out, size_t out_size, unsigned long long bytes)
{
    static char const * const unit_prefixes[] = {"", "Kilo", "Mega", "Giga", "Tera"};
    size_t const unit_prefixes_length = sizeof(unit_prefixes) / sizeof(unit_prefixes[0]);
    unsigned char unit_prefixes_index = 0;
    size_t const convert_bytes_every = 1024;

    while (bytes / convert_bytes_every > 0 && unit_prefixes_index < unit_prefixes_length) {
        bytes /= convert_bytes_every;
        unit_prefixes_index++;
    }

    snprintf(out, out_size, "%llu %sBytes", bytes, unit_prefixes[unit_prefixes_index]);

    return out;
}

int hostname_to_address(char const * const host, char const * const port, struct addrinfo ** const result)
{
    int s;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    s = getaddrinfo(host, port, &hints, result);
    if (s != 0) {
        return s;
    }

    return 0;
}

void strftime_local(double time_in_secs, char * const out, size_t out_size)
{
    time_t t = (time_t)time_in_secs;
    struct tm r;

    if (localtime_r(&t, &r) == NULL)
    {
        out[0] = '\0';
        return;
    }

    if (out_size > TIMESTAMP_STRLEN)
    {
        out_size = TIMESTAMP_STRLEN;
    }

    if (strftime(out, out_size, "%a, %d %b %Y %T %z", &r) <= 0)
    {
        out[0] = '\0';
        return;
    }
}
