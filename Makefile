# $Id: Makefile 90 2000-07-31 02:42:02Z marvin $
TARGETS=arping

CCFLAGS=-g

all: $(TARGETS)

%.o: %.c
	gcc -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` $<

O_arping=arping.o
arping: $(O_arping)
	gcc -g -o $@ $(O_arping) `libnet-config --libs` -lpcap

clean:
	rm -f *.o $(TARGETS)
