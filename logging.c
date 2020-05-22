#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"

#define LOGMSG_MAXLEN BUFSIZ
/* ANSI terminal color codes */
#define RESET "\x1B[0m"
#define GRN "\x1B[32;1m"
#define YEL "\x1B[33;1m"
#define RED "\x1B[31;1;5m"
#define BLU "\x1B[34;1;1m"
#define CYA "\x1B[36;1;1m"
#define DEF RESET

#ifdef DEBUG_BUILD
static log_priority lower_prio = LP_DEBUG;
#else
static log_priority lower_prio = NOTICE;
#endif

void log_fmt_colored(log_priority prio, const char * fmt, ...)
{
    char out[LOGMSG_MAXLEN + 1];
    va_list arglist;

    if (prio < lower_prio)
        return;

    assert(fmt);
    va_start(arglist, fmt);
    assert(vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0);
    va_end(arglist);

    switch (prio) {
        case LP_DEBUG:
            printf("[" DEF "DEBUG" RESET "]   %s\n", out);
            break;
        case NOTICE:
            printf("[" GRN "NOTICE" RESET "]  %s\n", out);
            break;
        case WARNING:
            printf("[" YEL "WARNING" RESET "] %s\n", out);
            break;
        case ERROR:
            printf("[" RED "ERROR" RESET "]   %s\n", out);
            break;
        case EVENT:
            printf("[" BLU "EVENT" RESET "]   %s\n", out);
            break;
        case PROTO:
            printf("[" CYA "PROTO" RESET "]   %s\n", out);
            break;
    }
}
