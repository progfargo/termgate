/* LVGL configuration. Every setting not listed here takes its default from lv_conf_internal.h. */
#ifndef LV_CONF_H
#define LV_CONF_H

#define LV_COLOR_FORMAT_DEFAULT LV_COLOR_FORMAT_XRGB8888

/* Use the C library for memory, strings and sprintf */
#define LV_USE_STDLIB_MALLOC LV_STDLIB_CLIB
#define LV_USE_STDLIB_STRING LV_STDLIB_CLIB
#define LV_USE_STDLIB_SPRINTF LV_STDLIB_CLIB

/* Load TTF fonts at runtime (for non-ASCII characters) */
#define LV_USE_TINY_TTF 1
/* The setup key of the second step as a QR code on the sign-in screen */
#define LV_USE_QRCODE 1

#define LV_USE_LOG 1
#define LV_LOG_LEVEL LV_LOG_LEVEL_WARN
#define LV_LOG_PRINTF 1

#define LV_BUILD_EXAMPLES 0


#endif
