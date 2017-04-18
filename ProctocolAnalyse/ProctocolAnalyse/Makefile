NO_WARN = -Wall
CC = gcc
DEBUG = -g

all:main

LIBS=-lpcap -lndpi
main:main.c ProtocolAnalyse.c
	$(CC) -o $@ $^ $(LIBS) $(NO_WARN)

debug:main.c ProtocolAnalyse.c
	$(CC) $(DEBUG) $(NO_WARN) -o main $^ $(LIBS)

clean:
	rm -rf main
