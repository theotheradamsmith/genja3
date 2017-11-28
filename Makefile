BIN = genja3 fingerprinter

MKDIRP := mkdir -p

CC = gcc
NONWALL_CFLAGS = -std=c11 -g -O2
CFLAGS = -Wall $(NONWALL_CFLAGS)

GENJA3_LIBS = -lpcap -lssl -lcrypto
FINGER_LIBS = -lm libujson4c.a

GENJA3_SRC = genja3.c parser.c pcap_engine.c util.c
FINGER_SRC = fingerprinter.c ja3_hashmap.c util.c

UJSON4C_OBJDIR := ujson4c/build

UJSON4C_SRC = \
	$(wildcard ujson4c/src/*.c) \
	$(wildcard ujson4c/3rdparty/*.c)

UJSON4C_OBS = $(patsubst %.c, %.o, $(UJSON4C_SRC))

all: $(BIN)

genja3: $(GENJA3_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(GENJA3_LIBS)

fingerprinter: $(FINGER_SRC) libujson4c.a
	$(CC) $(CFLAGS) -o $@ $^ $(FINGER_LIBS)

$(UJSON4C_OBJDIR)/%.o: %.c
	@$(MKDIRP) $(dir $@)
	$(CC) $(NONWALL_CFLAGS) -c $< -o $@

libujson4c.a: $(addprefix $(UJSON4C_OBJDIR)/, $(UJSON4C_OBS))
	ar rcs $@ $^

clean:
	rm -f genja3
	rm -f fingerprinter
	rm -rf ${CURDIR}/$(UJSON4C_OBJDIR)

realclean: clean
	rm libujson4c.a

.PHONY: directories clean libujson4c.a
