#ifndef LOGGING_H
#define LOGGING_H 1

#define LOG log_fmt_colored

typedef enum log_priority { LP_DEBUG = 0, NOTICE, WARNING, ERROR, EVENT, PROTO } log_priority;

extern log_priority lower_prio;

void log_fmt_colored(log_priority prio, const char * fmt, ...);

#endif
