# $Id: Makefile 59 2000-05-23 15:30:21Z marvin $
TARGETS=arping

all: $(TARGETS)

%.o: %.c
	gcc -Wall $(CFLAGS) -c `libnet-config --defines` `libnet-config --cflags` $<

O_arping=arping.o
arping: $(O_arping)
	gcc -g -o $@ $(O_arping) `libnet-config --libs` -lpcap

clean:
	rm -f *.o $(TARGETS)
