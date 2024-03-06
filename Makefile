CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Wextra -Werror
LDFLAGS=-lcrypto -lm

.PHONY: all
all: nyufile

nyufile: nyufile.o

nyufile.o: nyufile.c nyufile.h

.PHONY: clean

clean:
	rm -f nyufile nyufile.o
