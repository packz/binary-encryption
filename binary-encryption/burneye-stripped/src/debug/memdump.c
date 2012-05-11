/* memory dump utility
 * -scut
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>	/* basename */


void
hexdump (unsigned char *data, unsigned int amount);


int
main (int argc, char *argv[])
{
	pid_t			fpid;		/* child pid, gets ptraced */
	char *			argv0;
	struct user		regs;		/* PTRACE pulled registers */
	unsigned long int	addr,		/* segment start address */
				addr_end,	/* segment end address */
				len;		/* length of segment */
	unsigned long int	addr_walker,	/* walker to dump memory */
				eip;		/* current childs eip */

	/* array to temporarily store data into */
	unsigned char		data_saved[sizeof (unsigned long int)];

	/* file to read mapping information */
	FILE *			map_f;		/* /proc/<pid>/maps stream */
	unsigned char		map_line[256];	/* one line each from map */

	/* data for the dump files */
	FILE *			dump_f;		/* stream */
	char			dump_name[64];	/* filename buffer */


	if (argc < 3 || sscanf (argv[1], "0x%lx", &eip) != 1) {
		printf ("usage: %s <eip> <argv0 [argv1 [...]]>\n\n", argv[0]);
		printf ("will run 'argv0' as program with given arguments, "
				"until 'eip' is reached, then\n"
			"dumping 'len' bytes from 'addr'.\n\n"
			"example: %s 0x08049014 0x08048000 0x100 /bin/ls "
				"-l\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	argv0 = argv[2];

	fpid = fork ();
	if (fpid < 0) {
		perror ("fork");
		exit (EXIT_FAILURE);
	}
	if (fpid == 0) {	/* child */
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0) {
			perror ("ptrace PTRACE_TRACEME");
			exit (EXIT_FAILURE);
		}
		fprintf (stderr, "  child: TRACEME set\n");

		fprintf (stderr, "  child: executing: %s\n", argv[2]);
		close (1);
		dup2 (2, 1);
		execve (argv[2], &argv[2], NULL);

		/* failed ? */
		perror ("execve");
		exit (EXIT_FAILURE);
	}

	wait (NULL);

	memset (&regs, 0, sizeof (regs));

	if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}
	fprintf (stderr, "[0x%08lx] first stop\n", regs.regs.eip);

	/* now single step until given eip is reached */
	do {
		if (ptrace (PTRACE_SINGLESTEP, fpid, NULL, NULL) < 0) {
			perror ("ptrace PTRACE_SINGLESTEP");
			exit (EXIT_FAILURE);
		}
		wait (NULL);

		memset (&regs, 0, sizeof (regs));
		if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
			perror ("ptrace PTRACE_GETREGS");
			exit (EXIT_FAILURE);
		}
	} while (regs.regs.eip != eip);

	fprintf (stderr, "MEMDUMP: eip @ 0x%08lx, dumping...\n", eip);

	snprintf (dump_name, sizeof (dump_name), "%s.regs",
		basename (argv0));
	dump_name[sizeof (dump_name) - 1] = '\0';
	dump_f = fopen (dump_name, "w");
	if (dump_f == NULL) {
		perror ("fopen dumpfile regs");
		exit (EXIT_FAILURE);
	}
	fprintf (dump_f, "eax = 0x%08lx\n", regs.regs.eax);
	fprintf (dump_f, "ebx = 0x%08lx\n", regs.regs.ebx);
	fprintf (dump_f, "ecx = 0x%08lx\n", regs.regs.ecx);
	fprintf (dump_f, "edx = 0x%08lx\n", regs.regs.edx);
	fprintf (dump_f, "esi = 0x%08lx\n", regs.regs.esi);
	fprintf (dump_f, "edi = 0x%08lx\n", regs.regs.edi);
	fprintf (dump_f, "ebp = 0x%08lx\n", regs.regs.ebp);
	fprintf (dump_f, "esp = 0x%08lx\n", regs.regs.esp);
	fprintf (dump_f, "eflags = 0x%08lx\n", regs.regs.eflags);
	fprintf (dump_f, "xcs = 0x%08lx\n", regs.regs.xcs);
	fprintf (dump_f, "xds = 0x%08lx\n", regs.regs.xds);
	fprintf (dump_f, "xes = 0x%08lx\n", regs.regs.xes);
	fprintf (dump_f, "xss = 0x%08lx\n", regs.regs.xss);
	fclose (dump_f);

	snprintf (map_line, sizeof (map_line), "/proc/%d/maps", fpid);
	map_line[sizeof (map_line) -  1] = '\0';
	map_f = fopen (map_line, "r");
	if (map_f == NULL) {
		perror ("fopen map-file");

		exit (EXIT_FAILURE);
	}

	while (fgets (map_line, sizeof (map_line), map_f) != NULL) {
		char		map_perm[8];

		if (sscanf (map_line, "%08lx-%08lx %7[rwxp-] ",
			&addr, &addr_end, map_perm) != 3)
		{
			perror ("invalid map-line");

			exit (EXIT_FAILURE);
		}
		if (addr_end < addr) {
			fprintf (stderr, "sanity required, not so: "
				"addr = 0x%08lx, addr_end = 0x%08lx",
				addr, addr_end);

			exit (EXIT_FAILURE);
		}
		len = addr_end - addr;
		map_perm[sizeof (map_perm) - 1] = '\0';	/* ;-) */

		fprintf (stderr, "MEMDUMP: -> 0x%08lx (0x%08lx bytes, "
			"perm %s)\n", addr, len, map_perm);

		snprintf (dump_name, sizeof (dump_name),
			"%s.0x%08lx.0x%08lx.%s",
			basename (argv0), addr, len, map_perm);
		dump_name[sizeof (dump_name) - 1] = '\0';
		dump_f = fopen (dump_name, "wb");
		if (dump_f == NULL) {
			perror ("fopen dumpfile");

			exit (EXIT_FAILURE);
		}

		/* save data, assuming addr is page aligned */
		for (addr_walker = 0 ; addr_walker < len ;
			addr_walker += sizeof (data_saved))
		{
			errno = 0;

			*((unsigned long int *) &data_saved[0]) =
				ptrace (PTRACE_PEEKDATA, fpid,
					addr + addr_walker, NULL);

			if (errno == 0 && fwrite (&data_saved[0], 1, 4,
				dump_f) != 4)
			{
				perror ("fwrite dumpfile");

				exit (EXIT_FAILURE);
			} else if (errno != 0) {
				fprintf (stderr,
					"[0x%08lx] invalid PTRACE_PEEKDATA\n",
					addr + addr_walker);

				exit (EXIT_FAILURE);
			}
		}

		fclose (dump_f);
	}
	fclose (map_f);

	if (ptrace (PTRACE_DETACH, fpid, NULL, NULL) < 0) {
		perror ("ptrace PTRACE_DETACH");
		exit (EXIT_FAILURE);
	}

	fprintf (stderr, "MEMDUMP: success. terminating.\n");
	exit (EXIT_SUCCESS);
}



void
hexdump (unsigned char *data, unsigned int amount)
{
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";

	for (dp = 1; dp <= amount; dp++) {
		printf ("%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			printf (" ");
		if ((dp % 16) == 0) {
			printf ("| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				printf ("%c", trans[data[dp]]);
			printf ("\n");
		}
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			printf ("   ");
			if (((dp % 8) == 0) && (p != 8))
				printf (" ");
		}
		printf (" | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			printf ("%c", trans[data[dp]]);
	}
	printf ("\n");

	return;
}
