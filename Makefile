# 
# Projekt:	Monitorovanie hlaviciek HTTP
# Predmet: 	ISA 2014
# Autor:	Lubos Tichy
# Login:	xtichy23
# Subor:	Makefile
#

CC=g++
CFLAGS=-g -Wall -Wextra

httphdrs: main.o params.o sniff.o xml.o
	$(CC) $(CFLAGS) -o httphdrs main.o params.o sniff.o xml.o -lpcap

main.o: main.cpp main.hpp params.hpp sniff.hpp xml.hpp
	$(CC) $(CFLAGS) -c main.cpp

params.o: params.cpp params.hpp 
	$(CC) $(CFLAGS) -c params.cpp

sniff.o: sniff.cpp sniff.hpp 
	$(CC) $(CFLAGS) -c sniff.cpp

xml.o: xml.cpp xml.hpp
	$(CC) $(CFLAGS) -c xml.cpp

clean:
	 rm -f *.o 
