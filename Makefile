BIN = genja3

CC = gcc
CFLAGS = -Wall -std=c11 -g -O2
LIBS = -lpcap -lssl -lcrypto
SRC = genja3.c

all: $(BIN)

genja3: $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -rf genja3

.PHONY: clean
