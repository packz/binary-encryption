TOP	=	..
INCLUDE	=	-I. -I$(TOP) -I$(TOP)/include -I/usr/local/include
include $(TOP)/make.params

all: inject encrypt
	@cp inject encrypt $(TOP)/bin 

inject: util.o inject.c
	$(CC) -g $(CFLAGS) $(INCLUDE) -o inject inject.c util.o -lelf

encrypt: util.o encrypt.c
	$(CC) -g $(INCLUDE) -c -o encrypt.o encrypt.c
	$(CC) -o encrypt encrypt.o $(TOP)/obj/rc4.o util.o -lelf

util.o: util.c
	$(CC) -g $(CFLAGS) $(INCLUDE) -c -o $@ $< 

clean:
	/bin/rm -f *.o *~
