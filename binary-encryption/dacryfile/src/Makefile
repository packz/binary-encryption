TOP	=	..
include $(TOP)/make.params

INCLUDE	=	-I. -I$(TOP) -I$(TOP)/include 

SRC	=	\
		rc4.c 	\
		vx_main.c

OBJ	=	\
		rc4.o	\
		vx_main.o

all: $(OBJ)
	@cp $(OBJ) $(TOP)/obj

.c.o: $(SRC)
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

clean:
	/bin/rm -f *.o *~ 
