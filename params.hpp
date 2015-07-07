/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:	Lubos Tichy
 * Login:	xtichy23
 * Subor:	params.hpp
 */

#include <string>
#include <vector>

/* struktura parametrov */
struct sParam {
	std::string source;						// zdroj
	char type_of_source;					// typ zdroja
	unsigned int header_field_count;		// pocet poli hlaviciek
	std::vector<std::string> header_field;	// polia hlaviciek
	unsigned int port_count;				// pocet portov
	unsigned int *port;						// porty
	std::string output_file;				// vystupny xml subor
};

/* globalna premenna parametrov*/
extern struct sParam param;

/* inicializacia struktury parametrov predvolenymi hodnotami */
void init_struct_of_params();

/* ziskanie parametrov */
void get_params(int, char**);
