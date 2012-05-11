












#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int
main (int argc, char *argv[])
{
	unsigned char	i;
	unsigned int	dp = 0;	/* data pointer */


	while (read (0, &i, 1) > 0) {
		if (dp % 16 == 0)
			printf ("\"");

		printf ("\\x%02x", i);

		dp += 1;
		if (dp % 16 == 0)
			printf ("\"\n");
	}

	if (dp % 16 != 0)
		printf ("\";\n");
	else
		printf ("\"\";\n");

	exit (EXIT_SUCCESS);
}


