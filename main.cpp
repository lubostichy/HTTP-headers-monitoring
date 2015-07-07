/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:	Lubos Tichy
 * Login:	xtichy23
 * Subor:	main.cpp
 */

#include "main.hpp"
#include "params.hpp"
#include "sniff.hpp"
#include "xml.hpp"
#include <stdio.h>
#include <cstdlib>
#include <pcap.h>
#include <string>
#include <iostream>
#include <signal.h>

/*
 * osetrenie chyb
 */
void print_error(std::string str) {
	std::cerr <<  str << std::endl; 

	/* koniec s chybou */
	exit(1);
}

/* 
 * vycistenie pamate po alokacii
 */
void dispose() {
	for (unsigned int i = 0; i < param.port_count; i++) {
		free(param.port);
	}
}

/*
 * osetrenie zachyteneho signalu
 */
void signal_handler(int signo) {
	(void)signo;

	// zavrie rozhranie
	pcap_close(handle);
	
	/* zapisanie ziskanych informacii */
	write_XML();

	/* uspesny koniec programu */
	exit(0);
}

/******************************
 * 		MAIN 			
 ******************************/
int main(int argc, char **argv) {

	/* ziskanie parametrov */
	get_params(argc, argv);
	
	/* funkcie na odchytenie ukoncujuceho signalu pre cyklus pcap_loop */
	signal(SIGQUIT, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

    /* monitorovanie hlaviciek HTTP */
	sniff();	
	
	/* zapisanie ziskanych informaci */
	write_XML();

	/* uvolnenie alokovanej pamate */
	dispose();

	/* uspesny koniec programu */
	exit(0);
}