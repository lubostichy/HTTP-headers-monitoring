/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:	Lubos Tichy
 * Login:	xtichy23
 * Subor:	params.cpp
 */

#include "params.hpp"
#include "main.hpp"
#include "sniff.hpp"
#include <string>
#include <stdio.h>
#include <sstream>
#include <cstdlib>
#include <string>

struct sParam param;

/*
 *	inicializacia structury parametrov s predvolenymi hodnotami
 */
void init_struct_of_params() {

	param.source.clear();
	param.type_of_source = ' ';	
	param.header_field_count = 4;
	param.header_field.clear();
	param.header_field.push_back("User-Agent");
	param.header_field.push_back("Accept");
	param.header_field.push_back("Accept-Encoding");
	param.header_field.push_back("Accept-Language");
	param.port_count = 1;
	param.port = (unsigned int*) realloc(param.port, sizeof(unsigned int*) * param.port_count);
	param.port[0] = 80;
	param.output_file.clear();
}

/* 
 * ziskanie parametrov
 */
void get_params(int argc, char **argv) {

	int cur; 							// sucasny parameter
	std::string tmp_port_str;			// pomocny string pre porty
	tmp_port_str.clear();
	std::string tmp_header_field_str;	// pomocny string pre polia hlaviciek
	tmp_header_field_str.clear();


	/* inicializacia structury paramaterov */
	init_struct_of_params();

	if (argc == 1) {
		print_error("Wrong param!");
		return;
	}
	
	/* cyklus, v ktorom spracujeme parametre zadane od uzivatela */
	cur = 1;
	while (1) {		

		if (argv[cur][0] == '-') {
			switch (argv[cur][1]) {
				case 'f': {								// spracovanie parametru -f
					if (param.source.empty()) {
						param.type_of_source = 'f';		// zdroj je subor vo formate pcap
						cur++;
						if ((cur >= argc ) or (argv[cur][0] == '-')){				// parameter je naviac
							print_error("Wrong param!");
							return;
						}
						param.source = argv[cur];
					}
					else {
						print_error("Source is already defined!");
						return;
					}
					break;
				}
				case 'i': {								//spracovanie parametru -i
					if (param.source.empty()) {
						param.type_of_source = 'i';		// zdrojom su rozhrania
						cur++;
						if ((cur >= argc ) or (argv[cur][0] == '-')) {
							print_error("Wrong param!");
							return;
						}
						param.source = argv[cur];
					}
					else {
						print_error("Source is already defined!");
						return;
					}
					break;
				}
				case 'H': {		// spracovanie parametru -H
					if (tmp_header_field_str.empty()) {
						cur++;
						if ((cur >= argc ) or (argv[cur][0] == '-')) {
							print_error("Wrong param!");
							return;
						}
						tmp_header_field_str = argv[cur];		// ziska postupnost hlaviciek
					}
					else {
						print_error("Header specification is already defined!");
						return;
					}
					break;
				}
				case 'p': {		// spracovanie parametru -p
					if (tmp_port_str.empty()) {
						cur++;
						if ((cur >= argc ) or (argv[cur][0] == '-')) {
							print_error("Wrong param!");
							return;
						}
						tmp_port_str = argv[cur];	// ziska postupnost portov
					}
					else {
						print_error("Port is already defined!");
						return;
					}
					break;
				}

				case 'o': {		// spracovanie parametru -o
					if (param.output_file.empty()) {
						cur++;
						if ((cur >= argc ) or (argv[cur][0] == '-')) {
							print_error("Wrong param!");
							return;
						}
						param.output_file = argv[cur];	// ziska vystupny subor
					} 
					else {
						print_error("Output file is already defined!");
						return;
					}
					break;
				}

				default: {		// ina kombinacia z uvedenych je chybna
					print_error("Wrong param! default");
					return;
				}
				
			}
		}
		else {
			print_error("Wrong param! pomlcka nie je");
			return;
		}

		// prejde na dalsi parameter
		cur++;		
		if (cur >= argc) {
			break;
		}
	}

	// ak zdroj nie je definovany
	if (param.source.empty()) {
		print_error("Source is not defined!");
		return;
	}

	std::string token; // ziskany port z postupnosti

	if (!tmp_header_field_str.empty()) { // ak je specifikovany zoznam poli hlaviciek
		std::istringstream ss(tmp_header_field_str);
		param.header_field.clear();
		param.header_field_count = 1;
		while(getline(ss, token, ',')) {	// rozdeli postupnost podla ciarky	
			param.header_field.push_back(token);
			param.header_field_count++;
		}
		param.header_field_count--;
		
		/* upravim hlavicky zadane uzivatelom kvoli case-insensitive */
		unsigned int i;
		unsigned int pos;
		
		for (i = 0; i < param.header_field_count; i++) {
			pos = 0;
			/* osetrenie header field s nazvom "TE" */
			if ( !param.header_field[i].compare("te") ||
				 !param.header_field[i].compare("TE") ||
				 !param.header_field[i].compare("tE") ||
				 !param.header_field[i].compare("Te")) 
				{
					param.header_field[i] = "TE";
					continue;
				}
			while (pos != param.header_field[i].length()) {
				if (isalpha(param.header_field[i][pos])) {	// prve pismeno bude velke
					if (pos == 0) {
						param.header_field[i][pos] = toupper(param.header_field[i][pos]);
					}
					else {
						param.header_field[i][pos] = tolower(param.header_field[i][pos]); // ostatne za prvym pismenom su male
					}
				}
				else if (param.header_field[i][pos] == '-') { // prve pismeno za pomlckou bude velke
					pos++;
					if (param.header_field[i][pos] != '\0') {
						param.header_field[i][pos] = toupper(param.header_field[i][pos]);
					} else {
						pos--;
					}					
				}
				pos++;
			}
		}

		std::vector<std::string> tmp_field;
		for (i = 0; i < param.header_field_count; i++) {
			tmp_field.push_back("");
			tmp_field[i].clear();
		}
		unsigned int j;
		unsigned int count = 0;
		/* odstranim duplicitne */
		for (i = 0; i < param.header_field_count; i++) {
			for (j = 0; j < count; j++) {
				if (param.header_field[i] == tmp_field[j]) {
					break;
				}
			}
			if (j == count) {
				tmp_field[count] = param.header_field[i];
				count++;
			}

		}
		param.header_field_count = count;
		for (i = 0; i< param.header_field_count; i++) {
			if (!tmp_field[i].empty()) {
				param.header_field[i] = tmp_field[i];
			}
		}
	}

	if (!tmp_port_str.empty()) { // ak je specifikovany zoznam portov
		std::istringstream ss(tmp_port_str);			
		while (getline(ss, token, ',')) {	// rozdeli postupnost podla ciarky				
			param.port = (unsigned int * ) realloc (param.port, sizeof(unsigned int) * param.port_count);
			param.port[param.port_count - 1] = atoi(token.c_str());	// ulozi port do zoznamu
			if (param.port[param.port_count - 1] == 0) {
				print_error("Wrong param port!");
				return;
			}		
			param.port_count++;
		}

		param.port_count--;
	}	
	
	// ak nie je definovany vystupny subor
	if (param.output_file.empty()) {
		print_error("Output file is not defined!");
		return;
	}
}