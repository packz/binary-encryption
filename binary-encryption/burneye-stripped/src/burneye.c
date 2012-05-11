/* burneye - main wrapping functions
 * source distribution, enjoy! -sc
 */

#define	VERSION	"1.0-source"

#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>		/* getopt */
#include "stub/stubhdr.h"


/* prototypes
 */
void usage (char *progname);

void wrap (char *program, unsigned char *stub_data,
	unsigned long int stub_len);

unsigned long int getmaxbrk (unsigned char *elf);

unsigned char * file_read (char *pathname);


/*** global variables
 */
unsigned long int	entry_vaddr = 0;
unsigned long int	enc_start = 0;
unsigned long int	entry_next = 0;

char *			inputname = NULL;


/* output file options
 */
char *			outputname = "output";

stubhdr *		shdr;

#define	FILE_OFFSET(addr) (((unsigned char *)(addr)) - stub_data)


/* real stub included here, this is no common include, but a one-time include
 * it defines some very important values, which can be overwritten by .be
 * definition files though (TODO: not yet implemented, of course ;)
 */
#include "stub/stub-bin.h"


void
usage (char *progname)
{
	fprintf (stderr, "usage: %s [options] <program>\n\n", progname);

	fprintf (stderr,
		"generic options\n"
		"\t-o out\t\tspecify another output file name (default: output)\n");

	fprintf (stderr, "\n");

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	char			c;
	char *			progname = argv[0];

	unsigned long int	stub_len;
	unsigned char *		stub_data;


	printf ("burneye source distribution\n"
		"version "VERSION" for learning purposes\n"
		"------------------------------------------------------------"
		"-------------------\n\n");

	if (argc < 2)
		usage (progname);

	while ((c = getopt (argc, argv, "o:")) != EOF) {
		switch (c) {
		case 'o':
			outputname = optarg;
			break;
		default:
			usage (progname);
			break;
		}
	}

	inputname = argv[argc - 1];
	if (inputname[0] == '-')
		usage (progname);

	stub_len = sizeof (stub_bin) - 1;
	stub_data = malloc (stub_len + SHDR_MAXSIZE);
	memcpy (stub_data, stub_bin, stub_len);

	printf ("loaded %lu bytes @ 0x%08lx\n",
		stub_len, (unsigned long int) stub_data);

	wrap (inputname, stub_data, stub_len);
	free (stub_data);

	printf ("\n---------------------------------------------------------"
		"----------------------\n\n");


	exit (EXIT_SUCCESS);
}


void
wrap (char *program, unsigned char *stub_data, unsigned long int stub_len)
{
	FILE *			fexe;
	unsigned char *		exe_data;
	unsigned long int	exe_len;
	Elf32_Ehdr *		ehdr;
	Elf32_Phdr *		phdr;
	unsigned long int	maxbrk;
	unsigned char *		output;
	unsigned char *		shdr_sub;


	ehdr = (Elf32_Ehdr *) stub_data;
	phdr = (Elf32_Phdr *) (stub_data + ehdr->e_phoff);
	if (ehdr->e_phnum != 2) {
		fprintf (stderr, "stub.bin must have exactly two program "
			"headers, aborting.\n");

		exit (EXIT_FAILURE);
	}

	if (ehdr->e_shoff != 0) {
		fprintf (stderr, "stub.bin contains section headers, "
			"aborting.\n");
		
		exit (EXIT_FAILURE);
	}

	if (phdr[0].p_memsz != phdr[0].p_filesz) {
		fprintf (stderr, "first segment in stub.bin has diverging "
			"file/mem sizes, aborting.\n");

		exit (EXIT_FAILURE);
	}

	printf ("end of segment 1: 0x%08lx\n",
		(unsigned long int) (phdr[0].p_offset + phdr[0].p_memsz));

	if (stub_len != phdr[0].p_offset + phdr[0].p_memsz) {
		fprintf (stderr, "bogus bytes at the end, i.e. something "
			"between segments end and file end.\n");
		exit (EXIT_FAILURE);
	}

	fexe = fopen (program, "rb");
	if (fexe == NULL) {
		fprintf (stderr, "failed to open %s\n", program);
		exit (EXIT_FAILURE);
	}

	fseek (fexe, 0, SEEK_END);
	exe_len = ftell (fexe);
	fseek (fexe, 0, SEEK_SET);

	exe_data = malloc (exe_len);
	if (fread (exe_data, exe_len, 1, fexe) != 1) {
		fprintf (stderr, "failed to read %s into memory\n", program);
		exit (EXIT_FAILURE);
	}
	fclose (fexe);


	/* get maximum brk call we have to enforce. do this before the
	 * executeable is getting encrypted ;)
	 */
	maxbrk = getmaxbrk (exe_data);
	printf ("brk(0) to force is 0x%08lx\n", maxbrk);


	/* sizeof (unsigned long int), because we have the dummy magic value
	 * in there to detect the stub-running-on-its-own case */
	stub_len -= sizeof (unsigned long int);	/* dummy, be_stubhdr_u */
	shdr = (stubhdr *) (stub_data + stub_len);
	shdr->flags = 0x00000000;
	shdr->payload_len = exe_len;

	shdr_sub = ((unsigned char *) shdr) + sizeof (stubhdr);

	/* this is the real final lenght of the stub header, it does not
	 * change from below here
	 */
	shdr->stubhdr_size = (unsigned char *) shdr_sub -
		(unsigned char *) shdr;

	/* do not change anything here */
	stub_len += shdr->stubhdr_size;
	fprintf (stderr, "XXX: stub_len = 0x%08lx\n", stub_len);

	fprintf (stderr, "phdr 1 @ 0x%08lx\n", (unsigned long int) phdr[0].p_vaddr);
	fprintf (stderr, "phdr 2 @ 0x%08lx\n", (unsigned long int) phdr[1].p_vaddr);


	/* fixup program headers */
	phdr[0].p_filesz -= sizeof (unsigned long int);
	phdr[0].p_filesz += shdr->stubhdr_size;
	phdr[0].p_filesz += exe_len;

	phdr[0].p_memsz += exe_len;
	phdr[0].p_memsz += 0x1000 - (phdr[0].p_memsz % 0x1000);

	/* patch a zero sized second header to fix brk(0) value set by kernel.
	 * make it use the byte directly behind the first header.
	 */
	phdr[1].p_memsz = phdr[1].p_filesz = 0;
	phdr[1].p_vaddr = maxbrk;
	phdr[1].p_paddr = maxbrk;
	phdr[1].p_offset = phdr[0].p_offset + phdr[0].p_filesz;


	/* merge stub and executeable */
	output = malloc (stub_len + exe_len);
	memcpy (output, stub_data, stub_len);
	memcpy (output + stub_len, exe_data, exe_len);
	free (exe_data);


	/* dump new executeable to disk */
	fexe = fopen (outputname, "wb");
	if (fwrite (output, stub_len + exe_len, 1, fexe) != 1) {
		fprintf (stderr, "failed to write %lu output bytes to file 'output'\n",
			stub_len + exe_len);

		exit (EXIT_FAILURE);
	}

	fclose (fexe);
	chmod (outputname, S_IRUSR | S_IWUSR | S_IXUSR);

	free (output);

	return;
}


unsigned long int
getmaxbrk (unsigned char *elf)
{
	int			n;
	unsigned long int	mbrk = 0;
	Elf32_Ehdr *		ehdr = (Elf32_Ehdr *) elf;
	Elf32_Phdr *		phdr = (Elf32_Phdr *) (elf + ehdr->e_phoff);

	for (n = 0 ; n < ehdr->e_phnum ; ++n) {
		if (phdr[n].p_type != PT_LOAD)
			continue;

		if ((phdr[n].p_vaddr + phdr[n].p_memsz) > mbrk)
			mbrk = phdr[n].p_vaddr + phdr[n].p_memsz;
	}

	return (mbrk);
}


unsigned char *
file_read (char *pathname)
{
	FILE *		bf;
	unsigned char	c;
	unsigned int	cont_len;
	unsigned char *	cont = NULL;


	bf = fopen (pathname, "r");
	if (bf == NULL)
		return (NULL);

	/* yepp, its slow. f* caches internally though */
	for (cont_len = 0 ; fread (&c, 1, 1, bf) == 1 ; ++cont_len) {
		cont = realloc (cont, cont_len + 1);
		cont[cont_len] = c;
	}
	fclose (bf);

	cont = realloc (cont, cont_len + 1);
	cont[cont_len] = '\0';

	return (cont);
}


