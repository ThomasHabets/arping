# $Id: Makefile 24 2000-04-24 20:30:21Z marvin $
TARGETS=arping

%.o: %.c
	gcc -Wall $(CFLAGS) -c $(shell libnet-config --defines) $(shell libnet-config --cflags) $<

O_arping=arping.o
arping: $(O_arping)
	gcc -g -o $@ $(O_arping) $(shell libnet-config --libs) -lpcap

clean:
	rm -f *.o $(TARGETS)
