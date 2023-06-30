CPPFLAGS=$(shell pkg-config --cflags libcrypto)
CFLAGS=-Wall
LIBS=$(shell pkg-config --libs libcrypto)

all: totp

totp: totp.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

totp.o: totp.c
	$(CC) -c -o $@ $(CPPFLAGS) $(CFLAGS) $^

clean:
	rm -f totp totp.o

.PHONY: clean
