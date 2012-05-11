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

#include <linux/types.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <linux/mman.h>
#include <dirent.h>

#include <dl_libv2.h>
#include <elf.h>
#include <rc4.h>

inline __syscall3(int, mprotect, caddr_t, addr, size_t, len, int, prot);
inline __syscall2(int, mlock, caddr_t, addr, size_t, len);

/*
 * in order we want to do these things:
 *
 * 1) protect the .text segment: mprotect(3), mlock(3)
 *
 * 2) get the passphrase
 *
 * 3) decrypt the .text segment
 *
 * 4) re-protect the .text segment
 *
 * 5) return
 *
 */

/* 
 * encrypt from 
 * 	ehdr->e_entry - phdr->p_vaddr // == _start offset
 * to
 * 	phdr->p_filesz
 */

long entry;

int
vx_main (void)
{
//	extern void 	* entry;

	Elf32_Ehdr	* ehdr;
	Elf32_Phdr	* phdr;
	rc4_key		  key;
	int		  len,
			  i;
	char		  name[8],
			* pass,
			* p;
	void		* h,
			* me;
	long		  ptr;

	char		*(*getpass)(char *);
	int		 (*printf)(char *, ...);

	if ((h = dl_lib_init()) == NULL)
		return 1;

	if ((me = dl_lib_open(NULL, h)) == NULL)
		return 2;

	if ((ehdr=dl_lib_addr(me)) == NULL)
		return 3;

	phdr = (Elf32_Phdr *)((char *)ehdr + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) 
		if ((phdr->p_type == PT_LOAD) && !(phdr->p_flags&PF_W))
			break;

	if (phdr->p_type != PT_LOAD)
		return 4;

//	len = ((long)phdr->p_vaddr - (long)phdr->p_offset);
//	len -= (long)ehdr;
//
//	if (_mlock((void *)ehdr, len)<0)
//		return 5;

	if (_mprotect((void *)ehdr, phdr->p_filesz, (PROT_READ|PROT_WRITE))<0)
		return 6;

	name[0] = 'g';
	name[1] = 'e';
	name[2] = 't';
	name[3] = 'p';
	name[4] = 'a';
	name[5] = 's';
	name[6] = 's';
	name[7] = 000;

	if ((getpass = dl_lib_sym(name, h)) == NULL)
		return 7;

	name[0] = 'p';
	name[1] = 'r';
	name[2] = 'i';
	name[3] = 'n';
	name[4] = 't';
	name[5] = 'f';
	name[6] = 000;

	if ((printf = dl_lib_sym(name, h)) == NULL)
		return 7;

	name[0] = 'P';
	name[1] = 'a';
	name[2] = 's';
	name[3] = 's';
	name[4] = ':';
	name[5] = ' ';
	name[6] = 000;

	if ((pass = getpass(name)) == NULL)
		return 8;
	if (pass[strlen(pass)] == '\n')
		pass[strlen(pass)] = 000;

	name[0] = '%';
	name[1] = 's';
	name[2] = '\n';
	name[3] = '\0';

	printf(name, pass);

	prepare_key(pass, strlen(pass), &key);

	// memset wasn't inlined here.. for some reason.
	for (p = pass, len = strlen(pass); p < pass + len; p++)
		*p = 0x00;

	ptr = (long) &entry;
	// len = total size - (offset of _start)
	len = (long)phdr->p_filesz - ((long)ptr - (long)phdr->p_vaddr);

	name[0] = '%';
	name[1] = 'x';
	name[2] = ' ';
	name[3] = '%';
	name[4] = 'x';
	name[5] = ' ';
	name[6] = '\n';
	name[7] = '\0';

	printf(name, ptr, len);

	rc4(ptr, len, &key);
	memset(&key, 000, sizeof(key));

	if (_mprotect((void *)ehdr, phdr->p_filesz, (PROT_READ|PROT_EXEC))<0)
		return 9;

	return 0;
}
