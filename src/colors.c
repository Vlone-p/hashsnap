#include "colors.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

int g_use_color = 0;

void detect_color_support(void) {

    if (getenv("NO_COLOR")) {
        g_use_color = 0;
        return;
    }
    g_use_color = isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);
}

void print_err(const char *fmt, ...) {
    va_list args;
    fprintf(stderr, "%s%s", C_RED, C_BOLD);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "%s", C_RESET);
}

void print_warn(const char *fmt, ...) {
    va_list args;
    fprintf(stderr, "%s", C_YELLOW);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "%s", C_RESET);
}
