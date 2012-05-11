
#ifndef	COMMON_H
#define	COMMON_H

#include <sys/types.h>

void * xrealloc (void *m_ptr, size_t newsize);
char * xstrdup (char *str);
void * xcalloc (int factor, size_t size);

#endif

