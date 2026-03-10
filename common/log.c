#include "log.h"
#include <stdarg.h>
#include <time.h>
#include <string.h>

log_level_t g_log_level = LOG_INFO;

void log_set_level(log_level_t level)
{
    g_log_level = level;
}

void log_msg(log_level_t level, const char *fmt, ...)
{
    static const char *level_names[] = { "DEBUG", "INFO ", "WARN ", "ERROR" };
    struct timespec ts;
    struct tm       tm_info;
    char            time_buf[32];
    va_list         args;

    if (level < g_log_level) {
        return;
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_info);

    fprintf(stderr, "[%s.%03ld] [%s] ",
            time_buf,
            (long)(ts.tv_nsec / 1000000L),
            (level >= LOG_DEBUG && level <= LOG_ERROR)
                ? level_names[(int)level]
                : "?????");

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}
