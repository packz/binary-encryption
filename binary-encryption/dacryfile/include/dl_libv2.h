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

/*
 * libdl.h :
 * 	defines and function defs for libdl.c
 *
 * 	libdl.o needs to be linked in with the other object code to be loaded,
 * 	in order to provide its fucktionality.  
 *
 * 	libdl.o will allow the dynamic linking against libraries that the
 * 	host file has had mmapped into its address space.  libdl will not 
 * 	mmap in new libraries, but if you can get by with libc then you will
 * 	pretty much be OK.
 *
 * 	The interface is described below.
 * 	!! BE AWARE that this version of libdl uses the heap !!
 * 	if you require a stack based libdl, then uses libdl_stack, which
 * 	is availble in this distro..
 *
 */

#ifndef _LIB_DYN_LINKER__H
#define _LIB_DYN_LINKER__H

#include <elf.h>

#define __syscall1(type,name,type1,arg1) \
type _##name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1))); \
        return (type) __res; \
}

#define __syscall2(type,name,type1,arg1,type2,arg2) \
type _##name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
        return (type) __res; \
}

#define __syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type _##name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
                "d" ((long)(arg3))); \
        return (type) __res; \
}

#ifndef NULL
#define  NULL 	((void *)0)	/* to avoid stdio.h */
#endif
#define  BUFSIZ	4096		/* should be plenty */

struct lib_desc
{
	Elf32_Word	* l_buckets;	/* addr of the hash table */
	Elf32_Word	  l_nbuckets;	/* number of buckets in hash tab */
	Elf32_Word	  l_nchain;	/* number of elements in chain */
	Elf32_Word	* l_chain;	/* addr of the chain */
	Elf32_Sym	* l_symtab;	/* ptr to symbol table */
	char 		* l_strtab;	/* ptr to string table */
	char		* l_load_addr;	/* load address of the library */
	void		* l_handle;	/* handle from dlopen(), for dlcose() */
	struct lib_desc	* l_prev;	/* pointer to previous LibDesc */
	struct lib_desc	* l_next;	/* pointer to next LibDesc */
	/* These values are only intialized for the head of the list */
	void		*(*malloc)(unsigned long); /* fct ptr to malloc(3) */
	void		 (*free)(void *); /* fct ptr to free(3) */
	void		*(*dlopen)(char *, int, void *)
		__attribute__ ((regparm(3))); /* fct ptr to _dl_open() */
	void		 (*dlclose)(void *)
		__attribute__ ((regparm(1))); /* fct ptr to _dl_close() */
};

typedef struct lib_desc LibDesc;

/* PROTOTYPES */
void * dl_lib_init(void);
void   dl_lib_fini(void *h);
void * dl_lib_open(char *lib_name, void *head);
void * dl_lib_sym(char *sym_name, void *handler);
void * dl_lib_addr(void *handler);
void   dl_lib_close(void *lib, void *head);

#endif  /* _LIB_DYN_LINKER__H */
