# $Id: Makefile 41 2000-05-17 23:32:38Z marvin $
TARGETS=arping

all: $(TARGETS)

%.o: %.c
	gcc -Wall $(CFLAGS) -c $(shell libnet-config --defines) $(shell libnet-config --cflags) $<

O_arping=arping.o
arping: $(O_arping)
	gcc -g -o $@ $(O_arping) $(shell libnet-config --libs) -lpcap

clean:
	rm -f *.o $(TARGETS)
