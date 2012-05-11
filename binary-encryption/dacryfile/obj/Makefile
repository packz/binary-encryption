OBJ	=	\
		vx_main.o 	\
		rc4.o		\
		dl_libv2.o	\

all:
	ld -r crt1.o $(OBJ) -o para.o

crt1.o: 
	@echo "Can't do this mate... you need to make all the objects first"

clean:
	/bin/rm -f *.o *~

test:
	cp host.orig host
	../bin/encrypt
	../bin/inject
