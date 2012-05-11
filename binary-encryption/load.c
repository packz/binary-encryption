#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PAGESIZE	ELF_EXEC_PAGESIZE /* 4096 */


int
fatal(char *s)
{
	perror(s);
	exit(2);
}

unsigned long
load_elf(int fd, Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, char **ret_elf)
{
	unsigned long	  nloadcmds = 0,
			  maplength;
	long		  addr;
	int		  i,
			  mm_flags = MAP_PRIVATE,
			  mm_prot = (PROT_READ|PROT_WRITE);
	char		* elf_image;
	Elf32_Phdr	* ph;
	struct loadcmd {
		long	mapstart,
			mapend,
			dataend,
			allocend;
		off_t	mapoff;
	} loadcmds[ehdr->e_phnum], * l;

	memset(&loadcmds, 0x00, sizeof(struct loadcmd) * ehdr->e_phnum);

	for (i = 0, ph = phdr; i < ehdr->e_phnum; i++, ph++) {
		switch (ph->p_type) {
		case PT_LOAD:
			{
				struct loadcmd *c = &loadcmds[nloadcmds++];
				c->mapstart = ph->p_vaddr & ~(ph->p_align - 1);
				c->mapend = ((ph->p_vaddr + ph->p_filesz +
					PAGESIZE - 1) & ~(PAGESIZE - 1));
				c->dataend = ph->p_vaddr + ph->p_filesz;
				c->allocend = ph->p_vaddr + ph->p_memsz;
				c->mapoff = ph->p_offset & ~(ph->p_align - 1);
			}
		default:
			break;
		}
	}

	l = loadcmds;

	maplength = loadcmds[nloadcmds - 1].allocend - l->mapstart;

	/* create a memory map of the whole deal */
	if ((elf_image = mmap(NULL, maplength, mm_prot, mm_flags, fd, 0))==NULL)
		return -1;

	addr = (long)(elf_image - l->mapstart);

	mm_flags |= MAP_FIXED;
	while (l < &loadcmds[nloadcmds]) {
		if (l->mapend > l->mapstart)
			mmap((void*)(addr+l->mapstart), l->mapend - l->mapstart,
				mm_prot, mm_flags, fd, l->mapoff);

		if (l->allocend > l->dataend) {
			/* .bss section, should be zeroed. pffft! */
		}
		l++;
	}

	/* We return the mmaped ELF (in theory) */
	*ret_elf = (char *)elf_image;
	return maplength;
}

int
dump_it(char *elf_image, unsigned long elf_size)
{
	int		  i;
	Elf32_Ehdr	* ehdr;
	Elf32_Phdr	* phdr,
			* ph;
	unsigned long	  ent_off;


	ehdr = (Elf32_Ehdr *)elf_image;
	phdr = (Elf32_Phdr *)(elf_image + ehdr->e_phoff);

	for (i = 0, ph = phdr; i < ehdr->e_phnum; i++, ph++)
		if ((ph->p_type == PT_LOAD) && !ph->p_offset)
			break;

	ent_off = ehdr->e_entry - ph->p_vaddr;

	printf("Entry offset: %lu, _start size: %u, _init size: %u\n", 
			ent_off, sizeof(start_shell), sizeof(init_shell));

	

	return 0;
}

int
create_map(int elf_fd, char *out_name)
{
	unsigned long	  elf_size;
	int		  out_fd;
	char		  page[PAGESIZE],
			* elfmag = ELFMAG,
			* elf_image;
	Elf32_Ehdr	* ehdr;
	Elf32_Phdr	* phdr;


	if ((out_fd = open(out_name, O_RDWR|O_CREAT, 0600)) == -1)
		fatal("Couldn't open output file");

	if (read(elf_fd, page, sizeof(page)) != sizeof(page))
		fatal("read of test failed");

	ehdr = (Elf32_Ehdr *)page;
	if (memcmp(ehdr->e_ident, elfmag, SELFMAG))
		return (-1);
	/* We need the program headers to create the memory image */
	phdr = (Elf32_Phdr *)(page + ehdr->e_phoff);

	if ((elf_size = load_elf(elf_fd, ehdr, phdr, &elf_image)) < 0 )
		fatal ("Humungous error loading ELF binary");

	if (dump_it(elf_image, elf_size) < 0)
		fatal("dumping the file failed");

	if (write(out_fd, elf_image, elf_size) != elf_size)
		fatal("didn't work");

	return (0);
}

int
main (int argc, char **argv)
{
	int	  fd;
	char	  out_file[256];



	if (argc != 2) {
		printf("usage: %s <file to map>", argv[0]);
		exit(2);
	}

	if ((fd = open(argv[1], O_RDONLY)) == -1)
		fatal("open failed for test");

	snprintf(out_file, sizeof(out_file) -8, "%s.mapped", argv[1]);
	create_map(fd, out_file);

	return 0;
}
