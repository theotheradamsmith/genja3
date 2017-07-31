#gcc -std=c11 -o genja3 genja3.c -lpcap -lssl -lcrypto

CC=gcc
LIBS=-lpcap -lssl -lcrypto
CFLAGS=-std=c11 -g -O2

all: $(OBJ)
	$(CC) $(CFLAGS) -o genja3 genja3.c $(LIBS)

clean:
	rm -rf genja3
