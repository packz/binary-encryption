#!/bin/sh

#host.orig	The original file.

cat > a.c << __EOF__
#include <stdio.h>

static char 	* h = "Hello";

int
main (void)
{
	char	* w = "World";


	(void) printf("%s %s!\n", h, w);

	return (0);
}
__EOF__

gcc -o host.orig a.c
rm -f a.c

echo "Original:"
./host.orig

#host.enc	The encrypted file.
cp host.orig host.enc
../bin/encrypt host.enc

echo "Encrypted:"
./host.enc

# host.dac	The encrypted infected file.
cp host.enc host.dac
../bin/inject -f host.dac -p ../obj/para.o

echo "Decrypting:"
./host.dac

# host.dac can now be stripped, sstrip, or whatever...
