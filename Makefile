CC = gcc
CFLAGS = -Wall -g -I/usr/include/openssl
LDFLAGS = -lcrypto

all: server client

server: server.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f server client
