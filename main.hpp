/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:	Lubos Tichy
 * Login:	xtichy23
 * Subor:	main.hpp
 */

#include <string>

/*
 * osetrenie chyb
 */
void print_error(std::string);

/* 
 * vycistenie pamate po alokacii
 */
void dispose(void);

/*
 * osetrenie zachyteneho signalu
 */
void signal_handler(int );