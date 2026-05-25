CC = gcc
CFLAGS = -Wall -Wextra -std=c11

TARGETS = pke_server lodi_server lodi_client tfa_server tfa_client test_sender

all: $(TARGETS)

pke_server: pke_server.c common.h
	$(CC) $(CFLAGS) pke_server.c -o pke_server

lodi_server: lodi_server.c common.h
	$(CC) $(CFLAGS) lodi_server.c -o lodi_server

lodi_client: lodi_client.c common.h
	$(CC) $(CFLAGS) lodi_client.c -o lodi_client

tfa_server: tfa_server.c common.h
	$(CC) $(CFLAGS) tfa_server.c -o tfa_server

tfa_client: tfa_client.c common.h
	$(CC) $(CFLAGS) tfa_client.c -o tfa_client

test_sender: test_sender.c
	$(CC) $(CFLAGS) test_sender.c -o test_sender

clean:
	rm -f $(TARGETS) *.o *.out
