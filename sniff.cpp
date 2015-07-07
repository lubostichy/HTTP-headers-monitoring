/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:	Lubos Tichy
 * Login:	xtichy23
 * Subor:	sniff.cpp
 */

#include "sniff.hpp"
#include "main.hpp"
#include "params.hpp"
#include "xml.hpp"
#include <sstream>
#include <iostream>
#include <string>
#include <stdio.h>
#include <pcap/pcap.h>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <algorithm>


char errbuf[PCAP_ERRBUF_SIZE]; 	/* buffer  pre chybove hlasky */
pcap_t *handle;					/* handle zdroja */
struct bpf_program fp;			/* pointer na filtrovaci program */
bpf_u_int32 mask;				/* maska */
bpf_u_int32 net;				/* adresa */

unsigned int current_port = 0;	/* sucasny port zdroja */
std::string current_ip;			/* sucasna adresa zdroja */


/*
 * zaciatok komunikacie
 */
void sniff() {
	
	/* rozhodne ci je zdrojom zariadenie alebo subor */
	if (param.type_of_source == 'i') { //zdrojom je zariadenie
		sniff_from_device();
	} 
	else if (param.type_of_source == 'f') { // zdrojom je subor vo formate pcap
		sniff_from_file();
	}


}

/*
 * hladanie HTTP header fields 
 */
void get_my_fields(std::string text) {

	std::size_t pos;
	std::string str;
	str.clear();

	/* prechadzanie policok zadanym parametrom -H */ 
	for (unsigned int i = 0; i < param.header_field_count; i++) {
		pos = text.find(param.header_field[i]);  		// ziskanie poziciue zaciatku policka		
		if (text.at(pos + param.header_field[i].length()) == ':') {	// je na zaciatku a nasleduje za nim dvojbodka 
			if ((param.header_field[i].compare("TE")) || (param.header_field[i].length() > 2)) {
				str.clear();
				if (pos != std::string::npos) {					// pozicia nie je posledna - najdenie policka
					pos += param.header_field[i].length()+2; 	// ziskanie hodnoty policka : dlzka nazvu + ':' + ' '
					while (text.at(pos+1) != '\n') {  			// ziskanie hodnoty az po koniec riadku
						str += text.at(pos);
						pos++;
					}
					
					/* pridanie mena a ziskanej hodnoty */
					add_element_to_XML(current_ip, "\t\t\t<header name=\"" + param.header_field[i] + "\" value=\"" +  str + "\" />\n");

				}
			}
		}
	}

}

/*
 * spracovanie dat 
 */
void get_payload(const u_char *payload)
{
	/* pocet HTTP ziadosti */ 
	#define request_count 8

	/* typy HTTP ziadosti */
	const char * type_of_http_request[] = {
		"GET",
		"HEAD",
		"POST",
		"PUT",
		"DELETE",
		"CONNECT",
		"OPTION",
		"TRACE"
	};

	std::string text((char*) payload);
	std::string::size_type n;
	std::ostringstream convert;

	for (int i = 0; i < request_count; i++)  {
		n = text.find(type_of_http_request[i]);
		if (n == std::string::npos) {			
			if (i == request_count) return; // ak je posledny typ http request, tak skonci
		} else {
			if (n < 15) {	// je na zaciatku paketu

				convert.str("");	
				convert << current_port;

				/* pridanie zaciatocneho connection s portom */
				add_element_to_XML(current_ip, "\t\t<connection port=\"" + convert.str() + "\">\n");

				/* hladanie HTTP header fields */
				get_my_fields(text);

				/* uzavretenie connection */
				add_element_to_XML(current_ip, "\t\t</connection>\n");
			}
		}
	}

return;
}

/*
 * funkcia volana pre spracovanie paketu
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	(void)(*args);
	(void)(*header);
	const struct sniff_ethernet *ethernet;	/* ethernet hlavicka */
	const struct sniff_ip *ip;				/* IPV4 hlavicka */
	const struct sniff_ip6 *ip6;			/* IPv6 hlavicka*/
	const struct sniff_tcp *tcp;			/* TCP hlavicka */
	unsigned char *payload;					/* data */
	
	int size_ip;		/* velkost IP hlavicky */
	int size_tcp;		/* velkost TCP hlavicky */
	int size_payload;	/* velkost dat */

	/* definovanie ethernet hlavicky */
	ethernet = (struct sniff_ethernet*)(packet);

	/* ziskanie IP hlavicky */
	if (ntohs(ethernet->ether_type) == IPv6_ETHERTYPE) {	
		// IPv6
		ip6 = (struct sniff_ip6 *) (packet + SIZE_ETHERNET);

		/* IPv6 hlavicka ma vzdy velkost 40 */ 
		size_ip = IPv6_SIZE;

	} 
	else if (ntohs(ethernet->ether_type) == IPv4_ETHERTYPE) {													
		// IPv4
		ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
		// ziskanie velkosti IPv4 hlavicky
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			print_error("Error IP header length");
			return;
		}
	}
	else {
		// iny protokol
		return;
	}
	

	/* ziskanie sucasnej IP adresy zdroja */ 
	if (ntohs(ethernet->ether_type) == IPv6_ETHERTYPE) {
		// ak je IPv6
		char buff[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &(ip6->ip_src), buff, INET6_ADDRSTRLEN);
		current_ip = buff;
	}
	else {
		// ak je IPv4
		current_ip = inet_ntoa(ip->ip_src);
	}

	// pridanie noveho potencialneho addr elementu
	new_addr_element(current_ip);

	/* ziskanie TCP hlavicky */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	
	/* sucasny port zdroja */
	current_port = (unsigned int) ntohs(tcp->th_sport);

	/* ziskanie dat */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* ziskanie velkosti dat */ 
	if (ntohs(ethernet->ether_type) == IPv6_ETHERTYPE) {
		size_payload = ntohs(ip6->ip_len) - (size_ip + size_tcp);
	}
	else {
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	}

	/* ak su nejake data */
	if(size_payload > 0) {
		get_payload(payload);
	}

}

/*
 * zaciatok komunikacie so zariadenia
 */
void sniff_from_device() {

	/* ziska sietovu masku a sietovu adresu zdroja */
	if (pcap_lookupnet(param.source.c_str(), &net, &mask, errbuf) == -1) {
		std::cerr <<  "Error get mask for device!" << std::endl;
		net = 0;
		mask = 0;
	}

	/* otvorenie zdroja pre uzitie */
	handle = pcap_open_live(
		param.source.c_str(), 	// zariadenie
		SNAP_LENGTH,			// snapshot length
		1,						// promiscuous mode
		1000,					// read timeout
		errbuf);				// buffer pre chybove hlasenie

	if (handle == NULL) {
		print_error("Error open device");
		return;
	}

	/* pomocne premenne pre vytvorenie retazca s portami */
	std::string tmpPort;
	std::string str;
	std::ostringstream convert;
	std::string tmpOR;

	str.clear();
	tmpPort.clear();
	tmpOR.clear();

	/* vytvori retazec s portami v tvare "tcp port port1 or port2 or port3" */
	tmpPort = "tcp port ";
	for (unsigned int i = 0; i < param.port_count; i++) {

		convert.str("");
		convert << param.port[i];

		tmpPort += tmpOR + convert.str();

		tmpOR = " or ";
	}

	/* zostavi filter, zadanie portov z parametra */
	if (pcap_compile(handle, &fp, tmpPort.c_str(), 0, net) == -1) {
		print_error("Error parse filter!");
		return;
	}

	/* aplikuje ziskany filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		print_error("Error install filter!");
		return;
	}
		
	/* vycisti pamat po pcap_compile */
	pcap_freecode(&fp);		

	/* 
	 * spracuje packety zdroja v cykle 
	 * ak sa vyskytne packet, zavola sa funkcia "got_packet",
	 * v ktorej sa pracuje s danym packetom 
	 */
	pcap_loop(handle, -1,got_packet,NULL);
		

}	

/*
 * zaciatok komunikacie zachytenej v subore
 */
void sniff_from_file() {

	/* otvorenie suboru, v ktorom je zachytena komunikacia */
	handle = pcap_open_offline(param.source.c_str(), errbuf);

	if (handle == NULL) {
		print_error("Error open pcap file!");
		return;
	}

	/* pomocne premenne pre vytvorenie retazca s portami */
	std::string tmpPort;
	std::string str;
	std::ostringstream convert;
	std::string tmpOR;

	str.clear();
	tmpPort.clear();
	tmpOR.clear();

	/* vytvori retazec s portami v tvare "tcp port port1 or port2 or port3" */
	tmpPort = "tcp port ";
	for (unsigned int i = 0; i < param.port_count; i++) {

		convert.str("");
		convert << param.port[i];

		tmpPort += tmpOR + convert.str();

		tmpOR = " or ";
	}

	/* zostavi filter, zadanie portov z parametra */
	if (pcap_compile(handle, &fp, tmpPort.c_str(), 0, net) == -1) {
		print_error("Error parse filter!");
		return;
	}

	/* aplikuje ziskany filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		print_error("Error install filter!");
		return;
	}
		
	/* vycisti pamat po pcap_compile */
	pcap_freecode(&fp);		


	/* 
	 * spracuje packety zdroja v cykle 
	 * ak sa vyskytne packet, zavola sa funkcia "got_packet",
	 * v ktorej sa pracuje s danym packetom 
	 */
	pcap_loop(handle,-1,got_packet, NULL);

	// zavrie otvoreny subor
	pcap_close(handle);

}
