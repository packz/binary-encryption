
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"


void *
xrealloc (void *m_ptr, size_t newsize)
{
	void	*n_ptr;

	n_ptr = realloc (m_ptr, newsize);
	if (n_ptr == NULL) {
		fprintf (stderr, "realloc failed\n");
		exit (EXIT_FAILURE);
	}

	return (n_ptr);
}


char *
xstrdup (char *str)
{
	char	*b;

	b = strdup (str);
	if (b == NULL) {
		fprintf (stderr, "strdup failed\n");
		exit (EXIT_FAILURE);
	}

	return (b);
}


void *
xcalloc (int factor, size_t size)
{
	void	*bla;

	bla = calloc (factor, size);

	if (bla == NULL) {
		fprintf (stderr, "no memory left\n");
		exit (EXIT_FAILURE);
	}

	return (bla);
}


