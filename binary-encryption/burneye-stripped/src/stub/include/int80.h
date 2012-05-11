/* from hellkit by stealth
 */

#ifndef	INT80_H
#define	INT80_H

#include "unistd.h"

#ifndef _I386_FCNTL_H
#define O_RDONLY    00
#define O_WRONLY    01
#define O_RDWR      02
#define O_CREAT   0100
#define O_TRUNC  01000
#define O_APPEND 02000
#define F_DUPFD		0	/* Duplicate file descriptor.  */
#define F_GETFD		1	/* Get file descriptor flags.  */
#define F_SETFD		2	/* Set file descriptor flags.  */
#define F_GETFL		3	/* Get file status flags.  */
#define F_SETFL		4	/* Set file status flags.  */
#endif

/* from bits/termios.h */
#define	TCGETS		0x5401
#define	TCSETS		0x5402
#define	TCSETSW		0x5403
#define	TCSETSF		0x5404

#define	ISIG	0000001
#define	ECHO	0000010


typedef unsigned char	cc_t;
typedef unsigned int	speed_t;
typedef unsigned int	tcflag_t;

#define	NCCS	32

typedef struct {
	tcflag_t	c_iflag;	/* input mode flags */
	tcflag_t	c_oflag;	/* output mode flags */
	tcflag_t	c_cflag;	/* control mode flags */
	tcflag_t	c_lflag;	/* local mode flags */
	cc_t		c_line;		/* line discipline */
	cc_t		c_cc[NCCS];	/* control characters */
	speed_t		c_ispeed;	/* input speed */
	speed_t		c_ospeed;	/* output speed */
} termios;

/* from bits/utsname.h and sys/utsname.h */
#define _UTSNAME_LENGTH 65
#define _UTSNAME_DOMAIN_LENGTH _UTSNAME_LENGTH
#define _UTSNAME_NODENAME_LENGTH _UTSNAME_LENGTH

struct utsname {
	char	sysname[_UTSNAME_LENGTH];
	char	nodename[_UTSNAME_NODENAME_LENGTH];
	char	release[_UTSNAME_LENGTH];
	char	version[_UTSNAME_LENGTH];
	char	machine[_UTSNAME_LENGTH];
	char	domainname[_UTSNAME_DOMAIN_LENGTH];
};


/* from bits/mman.h */
#define	PROT_READ	0x1
#define	PROT_WRITE	0x2
#define	PROT_EXEC	0x4
#define	PROT_NONE	0x0
#define	MAP_SHARED	0x01
#define	MAP_PRIVATE	0x02
#define	MAP_TYPE	0x0f
#define	MAP_FIXED	0x10
#define	MAP_ANONYMOUS	0x20

/* from unistd.h */
#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2

extern int	errno;

#if 0
/* XXX: one would have to make a wrap-around cpp script to avoid defining
 *      the functions in their code as it happens now :/ that is the reason
 *      why we include every function un-macro'd
 */
_syscall3(int,lseek,int,fd,long,offset,int,whence);
#endif

static int mmap (void  *start, long length, int prot, int flags,
	int fd, long offset)
{
	long	ret;

	__asm__ __volatile__ (	"int	$0x80"
		: "=a" (ret)
		: "a" (__NR_mmap), "b" (&start));

	return (ret);
}


static inline int munmap (char *start, int length)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_munmap), "S" ((long)start),
			      "c" ((int)length): "bx");
	return ret;
}

static inline int ioctl (int d, int request, int argp)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_ioctl), "S" ((long)d),
			      "c" ((long)request), "d" ((long)argp): "bx");
	return ret;
}

static inline int fcntl (int fd, int cmd, long arg)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_fcntl), "S" ((long)fd),
			      "c" ((long)cmd), "d" ((long)arg): "bx");
	return ret;
}

static inline int lseek (int fd, unsigned long int offset, int whence)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_lseek), "S" ((long)fd),
			      "c" ((long)offset), "d" ((long)whence): "bx");
	return ret;
}

static inline int mprotect(void *addr, long len, int prot)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_mprotect), "S" ((long)addr),
			      "c" ((long)len), "d" ((long)prot): "bx");
	return ret;
}


static inline int read(int fd, void *buf, long count)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_read), "S" ((long)fd),
			      "c" ((long)buf), "d" ((long)count): "bx");
	return ret;
}


static inline int write(int fd, void *buf, long count)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_write), "S" ((int)fd),
			      "c" ((long)buf), "d" ((long)count): "bx");
	return ret;
}


static inline int execve(char *s, char **argv, char **envp)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_execve), "S" ((long)s),
			      "c" ((long)argv), "d" ((long)envp): "bx");
	return ret;
}


static inline int setreuid(int reuid, int euid)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_setreuid), "S" ((long)reuid),
			      "c" ((long)euid): "bx");
	return ret;
}

static inline int uname(struct utsname *un)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_uname), "S" ((long)un): "bx");
	return ret;
}

static inline int unlink(char *pathname)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_unlink), "S" ((long)pathname): "bx");
	return ret;
}

static inline int chroot(char *path)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_chroot), "S" ((long)path): "bx");
	return ret;
}

static inline int brk(void *addr)
{
	long	ret;

	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			      :"=a" (ret)
			      :"0" (__NR_brk), "S" (addr): "bx");
	return (ret);
}

static inline int _exit(int level)
{
	long	ret;

	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			      :"=a" (ret)
			      :"0" (__NR_exit), "S" (level): "bx");
	return (ret);
}

static inline int dup(int fd)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_dup), "S" (fd): "bx");
	return ret;
}


static inline int dup2(int ofd, int nfd)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_dup2), "S" (ofd), "c" (nfd): "bx");
	return ret;
}


static inline int open(char *path, int mode, int flags)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_open), "S" ((long)path),
			      "c" ((int)mode), "d" ((int)flags): "bx");
	return ret;
}



static inline int chdir(char *path)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_chdir), "S" ((long)path): "bx");
	return ret;
}

static inline int close(int fd)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_close), "S" ((int)fd): "bx");
	return ret;
}


static inline int chown(char *path, int uid, int gid)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_chown), "S" ((long)path),
			      "c" ((int)uid), "d" ((int)gid): "bx");
	return ret;
}

static inline int rename(char *oldpath, char *newpath)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_rename), "S" ((long)oldpath),
			      "c" ((int)newpath): "bx");
	return ret;
}

static inline int chmod(char *path, int mode)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_chmod), "S" ((long)path),
			      "c" ((int)mode): "bx");
	return ret;
}

static inline int sync(void)
{
	long ret;

	__asm__ __volatile__ ("int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_sync));

	return (ret);
}

static inline int fork(void)
{
	long ret;

	__asm__ __volatile__ ("int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_fork));

	return (ret);
}


#endif

