NO_WARN = -Wall
CC = gcc
DEBUG = -g

FIND_INCLUDE=-I/usr/include/mysql
FIND_LIB=-L/usr/lib/mysql
LIBS=-lpcap -lndpi -lpthread -lmysqlclient


all:main

main:main.c ProtocolAnalyse.c mysql.c
	$(CC) -o $@ $^ $(LIBS) $(NO_WARN) $(FIND_LIB) $(FIND_INCLUDE)

debug:main.c ProtocolAnalyse.c
	$(CC) $(DEBUG) $(NO_WARN) -o main $^ $(LIBS) $(FIND_LIB) $(FIND_INCLUDE)

clean:
	rm -rf main
