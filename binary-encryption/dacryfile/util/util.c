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
#include <stdio.h>

char *elf_dyn[] = {
	"DT_NULL",
	"DT_NEEDED",
	"DT_PLTRELSZ",
	"DT_PLTGOT",
	"DT_HASH",
	"DT_STRTAB",
	"DT_SYMTAB",
	"DT_RELA",
	"DT_RELASZ",
	"DT_RELAENT",
	"DT_STRSZ",
	"DT_SYMENT",
	"DT_INIT",
	"DT_FINI",
	"DT_SONAME",
	"DT_RPATH",
	"DT_SYMBOLIC",
	"DT_REL",
	"DT_RELSZ",
	"DT_RELENT",
	"DT_PLTREL",
	"DT_DEBUG",
	"DT_TEXTREL",
	"DT_JMPREL",
	"DT_BIND_NOW",
	"DT_INIT_ARRAY",
	"DT_FINI_ARRAY",
	"DT_INIT_ARRAYSZ",
	"DT_FINI_ARRAYSZ",
	NULL
};

int
dump_dynamic(Elf *elf)
{
	Elf32_Dyn	* dyn;
	Elf32_Phdr	* phdr;
	Elf32_Ehdr	* ehdr;
	char		* raw;
	int		  i;

	if ((phdr = elf32_getphdr(elf)) == NULL) {
		fprintf(stderr, "phdr == NULL");
		return (2);
	}

	if ((raw = elf_rawfile(elf, NULL)) == NULL) {
		fprintf(stderr, "raw == NULL");
		return (2);
	}

	for (;phdr->p_type != PT_DYNAMIC; phdr++)
		;

	dyn = (Elf32_Dyn *)(raw + phdr->p_offset);

	i = 0;
	while (dyn->d_tag != DT_NULL) {
		printf("[%d] ", i);

		if (dyn->d_tag < DT_NUM) 
			printf(" %s ", elf_dyn[dyn->d_tag]);
		else if (dyn->d_tag >= DT_LOPROC &&
				dyn->d_tag <= DT_LOPROC + DT_PROCNUM)
			printf(" LOPROC ");
		else if ((Elf32_Word)DT_VERSIONTAGIDX(dyn->d_tag) <
				DT_VERSIONTAGNUM)
			printf(" DT_VERSIONTAGNUM ");
		else if ((Elf32_Word)DT_EXTRATAGIDX(dyn->d_tag) < 
				DT_EXTRANUM)
			printf(" DT_EXTRANUM ");
		else
			printf(" b0rken ");

		printf("(%#x)\n", i * sizeof(Elf32_Dyn));

		dyn++;
		i++;
	}

	return 0;
}

Elf_Scn *
get_scnbyname(Elf *elf, char *name, int *num)
{
	Elf32_Ehdr	* ehdr;
	Elf_Scn		* scn;
	Elf32_Shdr	* shdr;
	Elf_Data	* data;
	int		  cnt,
			  tmp;

	if (!num)
		num = &tmp;
	
	*num = 0;

	if ((ehdr = elf32_getehdr(elf))==NULL)
		return NULL;

	if (((scn = elf_getscn(elf, ehdr->e_shstrndx)) == NULL) ||
	    ((data = elf_getdata(scn, NULL)) == NULL))
		return NULL;

	for (cnt = 1, scn = NULL; (scn = elf_nextscn(elf, scn)); cnt++) {
		if ((shdr = elf32_getshdr(scn)) == NULL)
			return NULL;

		if (! strcmp(name, (char *)data->d_buf + shdr->sh_name)) {
			*num = cnt;
			return scn;
		}
	}
	return NULL;
}

int
fatal(char *s)
{
	printf("%s\n%s\n", s, elf_errmsg(elf_errno()));
	exit(2);
}
