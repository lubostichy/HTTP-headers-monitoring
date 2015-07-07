/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:   Lubos Tichy
 * Login:   xtichy23
 * Subor:   xml.cpp
 */

#include "main.hpp"
#include "params.hpp"
#include "sniff.hpp"
#include "xml.hpp"
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>

std::vector<sXML> xml; /* premenna vektorov struktury pre zapis do xml suboru */

/*
 * pridanie elementu (header, connection) k adrese
 */
void add_element_to_XML(std::string addr, std::string new_element) {

 	/* ziskanie indexu ulozenych adries */
	int found = find_addr(addr);

	/* pridanie elementu do ziskanej adresy */
	if (found != -1) {
		xml[found].element.push_back(new_element);
	}

}

/*
 * pridanie novej potencialnej adresy
 */
void new_addr_element(std::string new_addr) {

	/* vyhladanie adresy v ulozenom zozname adries */
	int found = find_addr(new_addr);

	/* ulozenie novej adresy */
	if (found == -1) {
		struct sXML tmp;
		tmp.ip = new_addr;
		xml.push_back(tmp);
	}
}

/* vytvorenie xml suboru s pridanymi elementami */
void write_XML(){
	unsigned int i, j;
	std::ofstream xml_file;
	xml_file.open(param.output_file.c_str());	/* subor zadany parametrom -o */

	xml_file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"; // popis xml suboru do hlavicky 
	xml_file << "<httphdrs>\n";		// root element

	/* ak sa nasli nejake hlavicky */
	if (xml.size() != 0) {
		for (i = 0; i != xml.size(); i++) {
			if (xml[i].element.size() != 0) {	// ak existuje connection element
				xml_file << "\t<ip addr=\"" + xml[i].ip + "\">\n";		// vytvorenie ip elementu s adresou
				//std::cout << "\t<ip addr=\"" + xml[i].ip + "\">\n"; 
				for (j = 0; j != xml[i].element.size(); j++) {
					if (!xml[i].element[j].empty()) {
						xml_file << xml[i].element[j];	// zapisanie connection a header elementov
					} 
				}
				xml_file << "\t</ip>\n";			// koniec ip elementu
			}
		}
	}
	xml_file << "</httphdrs>\n"; // koniec root elementu
	

	/* uzavretie suboru po zapise */
	xml_file.close();
}

/*
 * vyhladanie adresy medzi potencialnymi adresami, vratenie indexu adresy
 */
int find_addr(std::string in_ip) {
	unsigned int i;
	for (i = 0; i != xml.size(); i++) {
		if (xml[i].ip.compare(in_ip) == 0) {
			return i;
		}
	}
	return -1;
}
