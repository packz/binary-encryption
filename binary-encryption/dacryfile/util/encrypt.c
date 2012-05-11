/*
 * Copyright (C) 2001 the grugq.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the grugq.
 * 4. The name the grugq may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <libelf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <rc4.h>

#define STRCMP(a, R, b) (strcmp(a, b) R 0)


Elf_Scn * get_scnbyname(Elf *elf, char *name, int *num);
int fatal(char *s);

int
usage(char *s)
{
	printf("%s [file to encrypt]\n", s);
	exit(EXIT_FAILURE);
}

int
main (int argc, char **argv)
{
	Elf32_Phdr	* phdr;
	Elf32_Ehdr	* ehdr;
	rc4_key		  key;
	int		  fd,
			  i = 0,
			  off;
	char		* file = NULL,
			* passw = NULL,
			  pass[256],
			* ptr,
			* buf;
	struct stat	  st;

	if (argc == 2)
		file = argv[1];
	else
		usage(argv[0]);

	do {
		if (i)
			printf("Passphrases don't match.\n");

		if ((passw = getpass("Passphrase: ")) == NULL) 
			fatal("Bad pass");

		memcpy(pass, passw, strlen(passw));

		if ((passw = getpass("Confirm phrase: ")) == NULL)
			fatal("Bad pass");
		i = 1;

	} while (STRCMP(passw, !=, pass));

	memset(pass, 0x00, sizeof(pass));

	if ((fd = open(file, O_RDWR, 0)) == -1)
		fatal("open host file");

	if (fstat(fd, &st) < 0)
		fatal("stat host file");

	if ((ptr = mmap(NULL, st.st_size, (PROT_READ|PROT_WRITE),
					MAP_SHARED, fd, 0)) == (void *)(-1))
		fatal("mmap failed");

	ehdr = (Elf32_Ehdr *)ptr;
	phdr = (Elf32_Phdr *)(ptr + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++, phdr++)
		if (phdr->p_type == PT_LOAD)
			break;

	off = ehdr->e_entry - phdr->p_vaddr;

	buf = (char *)(ptr + off);

	prepare_key(passw, strlen(passw), &key);
	rc4(buf, phdr->p_filesz - off, &key);

	return 0;
}
