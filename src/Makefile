CC=gcc
CFLAGS= -fno-stack-protector -g
DEPS = common.h server.h client.h udp.h udp_service.h rtt.h service.h

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	CFLAGS += -pthread -lm 
endif

	
common_client.o: common.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -D CLIENT

udp_service_client.o: udp_service.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -D CLIENT

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

client: client.o common_client.o udp.o udp_service_client.o rtt.o service.o 
	$(CC) -o $@ $^ $(CFLAGS) 

server: server.o common.o udp.o udp_service.o rtt.o service.o
	$(CC) -o $@ $^ $(CFLAGS) 

all: client server

debug: CFLAGS += -D DEBUG -Wall
debug: client server

clean:
	rm *.o client server
