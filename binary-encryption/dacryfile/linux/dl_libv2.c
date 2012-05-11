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
#include <linux/fcntl.h>
#include <linux/mman.h>
#include <linux/dirent.h>

#include "dl_libv2.h"


static void * lib_open(const char *lib_name, void *head, void *handle);

inline __syscall1(int, close, int, fd);
inline __syscall3(int, open, const char *, file, int, flag, int, mode);
inline __syscall3(ssize_t, read, int, fd, void *, buf, size_t, count);
inline __syscall3(ssize_t, write, int, fd, const void *, buf, size_t, count);

/* 
 * Elf hash function from the ABI.
 */
static unsigned long
elf_hash(const unsigned char *name)
{
	unsigned long	h = 0,
			g;
	
	while (*name) {
		h = (h << 4) + *name++;
		if ((g = h & 0xf0000000))
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

/* 
 * turn a string (i.e. "0401b000") into a pointer
 */
static void *
my_strtop(unsigned char *str, char **end)
{
	register unsigned char	  c,
				 *s;
	register long		  r = 0;

	s = str;
	for (c = *s; c != '\0'; c = *s++) {
		/* based on ASCII table order ;) */
		if ((c >= '0') && (c <= '9'))
			c -= '0';
		else if ((c >= 'A') && (c <= 'F'))
			c = (c - 'A') + 10;
		else if ((c >= 'a') && (c <= 'f'))
			c = (c - 'a') + 10;
		else
			break;
		r *= 16;
		r += c;
	}
	if (end)
		*end = s;
	return (void *)r;
}

/*
 * a simplistic non optimized strncmp(3)
 */
static int
my_strncmp(const char *s, const char *t, int len)
{
	register int i;

	for (i = 0; (*s == *t) && (i <= len); s++, t++, i++)
		if ((*s == '\0') || (i == len))
			return 0;
	return *s - *t;
}

static void *
add_node(LibDesc *head, LibDesc *ld)
{
	int	    f = 0;
	char	    name[7];
	LibDesc	  * ret,
		  * n;

	if (!head) {
		f = 1;
		head = ld;
		head->l_prev = NULL;

		name[0] = 'm';
		name[1] = 'a';
		name[2] = 'l';
		name[3] = 'l';
		name[4] = 'o';
		name[5] = 'c';
		name[6] = 0;

		if ((head->malloc = dl_lib_sym(name, head)) == NULL)
			return NULL;
	}
	else
		while (head->l_prev)
			head = head->l_prev;

	if ((ret = head->malloc(sizeof (LibDesc))) == NULL)
		return NULL;

	/* -O will make this inline asm... */
	memcpy(ret, ld, sizeof(LibDesc));

	n = head;
	while (n->l_next)
		n = n->l_next;

	n->l_next = ret;
	/* ugly hack to save the head of the list */
	if (!f)
		ret->l_prev = n;
	ret->l_next = NULL;

	return ret;
}

static void *
lib_open(const char *lib_name, void *head, void *lib_handle)
{
	int	 	  fd,
			  nread,
			  i;
	char		  name[16],	/* name buffer */
			  buf[BUFSIZ * 2],	/* read buffer */
			* text_start = NULL,	/* store for the .text addr */
			* p,	/* walking pointer */
			* q,	/* standing pointer */
			* s;	/* store for strcmp() */
	Elf32_Ehdr	* ehdr;
	Elf32_Phdr	* phdr;
	Elf32_Dyn	* dyn;
	LibDesc		* libd;

	/* enable pointer semantics */
	libd = alloca(sizeof(LibDesc));
	memset(libd, 0x00, sizeof(LibDesc));
	
	/* wish there was a cleaner way of not using .rodata... :-/ */
	/*    actually there is, using a few shifts to make an int of 
	 *    every four char's then assigning that to a walking int ptr*/
	name[ 0] = '/';
	name[ 1] = 'p';
	name[ 2] = 'r';
	name[ 3] = 'o';
	name[ 4] = 'c';
	name[ 5] = '/';
	name[ 6] = 's';
	name[ 7] = 'e';
	name[ 8] = 'l';
	name[ 9] = 'f';
	name[10] = '/';
	name[11] = 'm';
	name[12] = 'a';
	name[13] = 'p';
	name[14] = 's';
	name[15] = '\0';

	if ((fd = _open(name, O_RDONLY, 0)) <0)
		return NULL;

	/* memset becomes inline ASM with -O */
	memset(buf, 0x00, sizeof(buf));

	/* we read because we can't mmap(2) /proc... */
	if ((nread = _read(fd, buf, sizeof buf)) < 0)
		return NULL;
	/* tidy up, need to leave the exec's environment as clean as possible */
	(void)_close(fd);

	/* 
	 * here begins the hairy algo.
	 *
	 * We parse out a line of /proc/self/maps 
	 * then we check to see if it is our library, if it is, then we
	 * need to save pointers to its .text string...
	 * 
	 * later we can parse the string and determine pointers..
	 */
    if (lib_name) {
	for (i=0; i < nread; i++) {
		int	in_lib = 0;

		s = q = buf + i;
		/* find end of string without walking off the stack... */
		while ((*q != '\n') && (*q != '\0') && (i < nread)) {
			q++;
			i++;
		}
		*q = 0x00;	/* terminate the string, for debugging */

		/* check to see if we match the string */
		for (p = q; (p > s) && (*p != ' '); p--) {
			if (! my_strncmp(lib_name, p, strlen(lib_name)-1)) {
				in_lib = 1;
				break;
			}
		}

		/*  accounting is all updated, so just try again... */
		if (!in_lib)
			continue;

		/* seek past the '04xxx-04xxx' to the first space */
		for (p = s; (p < q) && (*p != ' '); p++) 
			;
		/* point to the protection string */
		p++;

		/* determine if we are looking at a .text segment,
		 * or a .data segment... */
		if ((p[0] == 'r') && (p[1] == '-') && (p[2] == 'x'))
			text_start = s;
		else 
			;

		/* if we got what we come for, piss off */
		if (text_start)
			break;
	}

	
	/* the .data segment has the PT_DYNAMIC and has to follow the .text
	 * segment.  This is a "feature", rather than a hard and fast rule, but
	 * it is reliable enough for almost all cases. This need not be true
	 * for PIC code (as in a library) and that bastard the owl might go
	 * and make this very annoying, but I don't think that is enough of
	 * an incentive to alter this code.
	 *
	 * It is, of course, quite trivial to add support for searching for the
	 * .data, in fact I have taken code out which did just that.  The code
	 * was not needed and I felt it more imporant that this code be clear,
	 * rather than comprehensive.
	 *
	 * It is sufficient for now.
	 *
	 * the .text segment has the elf and program headers, and the .data
	 * should follow immediatly afterwards.  The .data will have the
	 * dynamic linkage pointers so we can locate the hash table, string
	 * table, etc. etc.
	 */
	libd->l_load_addr = my_strtop(text_start, &p); 

	ehdr =(Elf32_Ehdr *) libd->l_load_addr;
	phdr =(Elf32_Phdr *)(libd->l_load_addr + ehdr->e_phoff);

	while (phdr->p_type != PT_DYNAMIC)
		phdr++;

	/* the .dynamic is in the .data segment, but we can just use the
	 * load address to locate it in memory.  non-portable? */
	/* The correct way to do this is to use p_offset and p_align to
	 * calculate the location of the start of the .data and .dynamic
	 * segments... but this way works quite nicely */
	dyn  = (Elf32_Dyn *) (libd->l_load_addr + phdr->p_vaddr);

	/* 
	 * I can't understand why l_hash needs the load_addr added to it, 
	 * and the other locations don't.  It seems they are intialized
	 * by the rtdl and DT_HASH isn't; but I can't say for sure...
	 */
	for (; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag == DT_HASH)
			libd->l_buckets = (void *)((long)dyn->d_un.d_ptr +
					(long)libd->l_load_addr);
		else if (dyn->d_tag == DT_SYMTAB)
			libd->l_symtab = (void *)dyn->d_un.d_ptr;
		else if (dyn->d_tag == DT_STRTAB)
			libd->l_strtab = (void *)dyn->d_un.d_ptr;
		else
			continue;
	}

	libd->l_nbuckets = *libd->l_buckets++;
	libd->l_nchain   = *libd->l_buckets++;
	libd->l_chain    = &(libd->l_buckets[libd->l_nbuckets]);

	libd->l_handle = lib_handle;
    }
    else
	libd->l_load_addr = my_strtop(buf, &p);

	return (add_node(head, libd));
}

void *
dl_lib_init(void)
{
	char	name[10];
	LibDesc	*head;

	name[0] = '/';
	name[1] = 'l';
	name[2] = 'i';
	name[3] = 'b';
	name[4] = 'c';
	name[5] = '-';
	name[6] =  0;

	if ((head =(LibDesc *)lib_open(name, NULL, NULL)) == NULL)
		return NULL;
	/* we resolve almost all of the functions we will need right here,
	 * this will save some execution time for apps which do multiple 
	 * dl_lib_open()s... 
	 *
	 * The penalty for code which only does a single dl_lib_init() is 
	 * minimal, so I don't mind this sacrifice.
	 *
	 * The only thing that needs to be pointed out is that this is not OOP.
	 * Don't even think about accusing me of that malarky. 
	 */

	name[0] = 'f';
	name[1] = 'r';
	name[2] = 'e';
	name[3] = 'e';
	name[4] =  0;

	if ((head->free = dl_lib_sym(name, head)) == NULL)
		return NULL;

	name[0] = '_';
	name[1] = 'd';
	name[2] = 'l';
	name[3] = '_';
	name[4] = 'o';
	name[5] = 'p';
	name[6] = 'e';
	name[7] = 'n';
	name[8] =  0;

	if ((head->dlopen = dl_lib_sym(name, head)) == NULL)
		return NULL;

	name[0] = '_';
	name[1] = 'd';
	name[2] = 'l';
	name[3] = '_';
	name[4] = 'c';
	name[5] = 'l';
	name[6] = 'o';
	name[7] = 's';
	name[8] = 'e';
	name[9] =  0;
	
	if ((head->dlclose = dl_lib_sym(name, head)) == NULL)
		return NULL;

	return ((void *)head);
}

void
dl_lib_fini(void *h)
{
	LibDesc		*head,
			*node;

	head = (LibDesc *)h;

	if (!head)
		return;

	while (head->l_prev)
		head = head->l_prev;

	/* seek the tail of the list */
	for (node = head; node->l_next; node = node->l_next)
		;

	/* walk up backwards, closing everything */
	for (; node; node = node->l_prev)
		dl_lib_close(node, head);

	/* it should all be done */
	return;
}

void
dl_lib_close(void *l, void *h)
{
	LibDesc		*head,
			*ld;

	ld = (LibDesc *)l;
	head = (LibDesc *)h;
	if (!ld || !h)
		return;

	while (head->l_prev)
		head = head->l_prev;


	/* if we have a dlopen() handle, we can close it */
	
	if (ld->l_handle)
		head->dlclose(ld->l_handle);

	head->free(ld);
	ld = NULL;	/* prevent silliness */

	return;
}

void *
dl_lib_open(char *lib_name, void *h)
{
	void	* handle;
	LibDesc	* head;

	head = (LibDesc *)h;

	if (!head)
		return NULL;

	/* seek the head of the linked list */
	while (head->l_prev)
		head = head->l_prev;

	if (lib_name)
		if ((handle = head->dlopen(lib_name, 1,
					__builtin_return_address(0))) == NULL)
			return NULL;
	/* we have successfully mapped the library into our space, now
	 * all we need to do is intialize our usual LibDesc for it */
	return (lib_open(lib_name, head, handle));
}

void *
dl_lib_sym(char *sym_name, void *handler)
{
	Elf32_Sym	* sym,
			* symtab;
	int		  hn,
			  ndx;
	char 		* strs;
	LibDesc		* libd = (LibDesc *)handler;
	
	if (!sym_name || !libd)
		return NULL;

	strs = libd->l_strtab;
	symtab = libd->l_symtab;

	hn = elf_hash(sym_name) % libd->l_nbuckets;

	/* we need to "follow the chain" until we find our function... */
	for (ndx = libd->l_buckets[hn]; ndx; ndx = libd->l_chain[ndx]) {
		sym = symtab + ndx;

		if ((ELF32_ST_TYPE(sym->st_info) == STT_FUNC) &&
			(!my_strncmp(strs + sym->st_name, sym_name,
				     strlen(sym_name) - 1))) {
			/* we found it! rejoice the king has cum. */
			return ((void *)((long)sym->st_value +
						(long)libd->l_load_addr));
		}
	}

	/* we have totally bombed out.  There is no symbol by that name in the
	 * symtab... sorry :-( */
	return NULL;
}

void *
dl_lib_addr(void *handler)
{
	LibDesc *ld = handler;

	return ((void *)ld->l_load_addr);
}

