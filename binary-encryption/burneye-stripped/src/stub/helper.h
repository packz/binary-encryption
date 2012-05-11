/* helper functions include file
 */

#ifndef	HELPER_H
#define	HELPER_H

#ifdef VDEBUG
#include <stdarg.h>
#endif

#ifndef NULL
#define	NULL ((void *) 0)
#endif

#ifndef VDEBUG
#define be_printf(str,a...)
#else
void be_printf (char *str, ...);
int vsnprintf(char *str, int count, const char *fmt, va_list args);
#endif

int memcmp (void *dst, void *src, unsigned int len);
void memcpy (void *dst, void *src, unsigned int len);
void memset (void *dst, unsigned char c, unsigned int len);
int strlen (unsigned char *str);

#endif


