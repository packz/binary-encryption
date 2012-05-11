ifeq ($(debug),on)
CFLAGS += -g -ggdb
DFLAGS += -DDEBUG -DVDEBUG
MPASS += debug=on
endif

CFLAGS += -Wall $(DFLAGS)

CC=gcc
OBJS =	common.o


# basic targets
#

all:	debug stub/stub.bin burneye.c $(OBJS)
	$(CC) $(CFLAGS) -o burneye burneye.c $(OBJS)


# clean targets
#

clean:
	rm -f debug/memdump
	rm -f *.o burneye
	rm -f output
	make -C stub clean


# debug targets
#

debug:	debug/memdump

debug/memdump:	debug/memdump.c
	$(CC) $(CFLAGS) -o debug/memdump debug/memdump.c


# sub targets
stub/stub.bin:
	make -C stub rel=on $(MPASS) clean all

