#ifndef COLORS_H
#define COLORS_H

extern int g_use_color;

#define C_RESET   (g_use_color ? "\033[0m"  : "")
#define C_BOLD    (g_use_color ? "\033[1m"  : "")
#define C_DIM     (g_use_color ? "\033[2m"  : "")
#define C_GREEN   (g_use_color ? "\033[32m" : "")
#define C_CYAN    (g_use_color ? "\033[36m" : "")
#define C_YELLOW  (g_use_color ? "\033[33m" : "")
#define C_RED     (g_use_color ? "\033[31m" : "")
#define C_MAGENTA (g_use_color ? "\033[35m" : "")

void detect_color_support(void);
void print_err(const char *fmt, ...);
void print_warn(const char *fmt, ...);

#endif
