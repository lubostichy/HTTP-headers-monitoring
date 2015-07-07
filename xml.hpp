/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:   Lubos Tichy
 * Login:   xtichy23
 * Subor:   xml.hpp
 */

#include <string>

/* struktura pre vystupny xml subor */
struct sXML{
	std::string ip;
	std::vector<std::string> element;
};

/* pridanie elementu - header, connection */
void add_element_to_XML(std::string, std::string);

/* pridanie novej potencialnej adresy */
void new_addr_element(std::string);

/* vytvorenie xml suboru s pridanymi elementami */
void write_XML();

/* vyhladanie adresy medzi potencialnymi adresami, vratenie indexu adresy */
int find_addr(std::string);