
ifeq ($(debug),on)
CFLAGS += -g -ggdb
DFLAGS += -DDEBUG -DVDEBUG
endif
ENTRY_POINT = be_entry

DFLAGS += -DIN_STUB

CFLAGS += -Wall -fconserve-space -Os -fno-builtin $(DFLAGS)

OBJS =	helper.o init.o stub.o snprintf.o


# basic targets
#
# all = generic stub-only target
# rel = target when creating real stub
#

all:	buildtools stub.bin.h


# clean target
#

clean:
	make -C utils clean
	rm -f *.o *.map *.bin
	rm -f utils/sstrip
	rm -f stub-bin stub-bin.lds stub-bin.h


# main stub target
#

stub.bin:	buildtools $(OBJS) stub.lds
	sed s/entry_point/$(ENTRY_POINT)/ < stub.lds > stub-bin.lds
	ld -Map stub.map -s -T stub-bin.lds -o stub.bin $(OBJS)
	rm -f stub-bin.lds
	utils/sstrip stub.bin

stub.bin.h:	stub.bin
	echo "unsigned char	stub_bin[] =" > stub-bin.h
	utils/hdump < stub.bin >> stub-bin.h

#
# tool target
#

buildtools:
	make -C utils all

hdump:	utils/hdump.c
	$(CC) -o utils/hdump -O2 -Wall utils/hdump.c


# special initial entry point target
init.o:	init.asm
	nasm $(DFLAGS) -f elf -o init.o init.asm

