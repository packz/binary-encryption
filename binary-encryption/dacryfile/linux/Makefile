TOP	=	..
INCLUDE	= 	-I. -I$(TOP) -I$(TOP)/include

include $(TOP)/make.params

OBJ	=	\
		crt1.o	\
		dl_libv2.o

all: $(OBJ)
	@cp $(OBJ) $(TOP)/obj

dl_libv2.o: dl_libv2.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

crt1.o: start.S
	as start.S -o crt1.o

clean:
	/bin/rm -f *.o *~
