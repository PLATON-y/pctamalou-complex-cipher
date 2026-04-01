CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -std=c99
LDFLAGS = -lm

all: libpctamalou.so test_pctamalou

libpctamalou.so: pctamalou_core.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

test_pctamalou: test_pctamalou.c libpctamalou.so
	$(CC) $(CFLAGS) -o $@ test_pctamalou.c -L. -lpctamalou -Wl,-rpath,.

test: test_pctamalou
	./test_pctamalou

bench: test_pctamalou
	./test_pctamalou bench

clean:
	rm -f libpctamalou.so test_pctamalou

.PHONY: all test bench clean
