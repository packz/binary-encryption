/* burneye - stub appended header
 *
 * -scut
 *
 * this is appended to the stub binary. see stub.lds, stub.c and wrap.c
 * for further description
 */

#ifndef	BURNEYE_STUBHDR_H
#define	BURNEYE_STUBHDR_H

typedef struct {
	unsigned long int	stubhdr_size;	/* length of this header */
	unsigned long int	payload_len;	/* length of payload */
	unsigned long int	flags;		/* generic flags */
} stubhdr;

#define	SHDR_MAXSIZE	(sizeof (stubhdr))
#endif


