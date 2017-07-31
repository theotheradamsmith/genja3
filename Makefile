#gcc -std=c11 -o genja3 genja3.c -lpcap -lssl -lcrypto

CC=gcc
LDFLAGS=-lpcap -lssl -lcrypto
CFLAGS=-std=c11 -g -O2

all: $(OBJ)
	$(CC) $(CFLAGS) -o genja3 genja3.c $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf genja3

