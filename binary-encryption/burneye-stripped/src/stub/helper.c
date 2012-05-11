/* helper functions
 */

#include <stdarg.h>
#include "include/int80.h"
#include "include/unistd.h"
#include "helper.h"


void
memset (void *dst, unsigned char c, unsigned int len)
{
	unsigned char *	p = (unsigned char *) dst;

	while (len--)
		*p++ = c;
}


int
memcmp (void *dst, void *src, unsigned int len)
{
	unsigned char *	d = (unsigned char *) dst;
	unsigned char *	s = (unsigned char *) src;

	while (len-- > 0) {
		if (*d++ != *s++)
			return (1);
	}

	return (0);
}


void
memcpy (void *dst, void *src, unsigned int len)
{
	unsigned char *	d = (unsigned char *) dst;
	unsigned char * s = (unsigned char *) src;

	while (len--)
		*d++ = *s++;
}


int
strlen (unsigned char *str)
{
	int	n = 0;

	while (*str++)
		n++;

	return (n);
}



#ifdef VDEBUG
void
be_printf (char *str, ...)
{
	int	len;
	va_list	vl;
	char	buf[1024];

	va_start (vl, str);
	len = vsnprintf (buf, sizeof (buf), str, vl);
	va_end (vl);
	buf[sizeof (buf) - 1] = '\0';

	write (1, buf, len);

	return;
}
#endif



