BIN = genja3

CC = gcc
CFLAGS = -Wall -std=c11 -g -O2
LIBS = -lpcap -lssl -lcrypto
SRC = genja3.c parser.c pcap_engine.c util.c

all: $(BIN)

genja3: $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f genja3

.PHONY: clean
