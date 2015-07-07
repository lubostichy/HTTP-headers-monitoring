/*
 * Projekt: Monitorovanie hlaviciek HTTP
 * Predmet: ISA 2014
 * Autor:   Lubos Tichy
 * Login:   xtichy23
 * Subor:   sniff.hpp
 */

#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string>


/* maximalna standardna velkost bytov zachyteneho paketu */
#define SNAP_LENGTH 1518 // 1500

/* velkost 14 bytov ethernet hlavicky */
#define SIZE_ETHERNET 14

/* velkost 6 bytovej ethernet addresy */
#define ETHER_ADDR_LEN	6

/* IPv6 typ hlavicky */
#define IPv6_ETHERTYPE 0x86DD

 /* IPv4 typ hlavicky */
 #define IPv4_ETHERTYPE 0x0800

/* velkost IPv6 hlavicky */
#define IPv6_SIZE 40

/* ethernetova hlavicka */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* adresa ciela */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* adresa zdroja */
        u_short ether_type;                     /* IP? ARP? RARP? ... */
};

/* struktura IPv4 hlavicky */
struct sniff_ip {
        u_char  ip_vhl;                 /* verzia */
        u_char  ip_tos;                 /* typ sluzby */
        u_short ip_len;                 /* celkova dlzka */
        u_short ip_id;                  /* identifikacia */
        u_short ip_off;                 /* offset */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* zivotnost TTL */
        u_char  ip_p;                   /* protokol */
        u_short ip_sum;                 /* kontrolny sucet */
        struct in_addr ip_src;          /* zdrojova adresa */
        struct in_addr ip_dst;          /* cielova adresa */
};

/* struktura IPv6 hlavicky */
struct sniff_ip6 {
        uint32_t        ip_vtcfl;       /* verzia + trieda provozu + znacka toku */
        uint16_t        ip_len;         /* dlzka dat */
        uint8_t         ip_nxt;         /* dalsia hlavicka (protocol) */
        uint8_t         ip_hopl;        /* max skokov(ttl) */
        struct in6_addr ip_src;         /* zdrojova adresa */
        struct in6_addr ip_dst;         /* cielova adresa */
};


/* vykona AND s cislom 15 */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

//#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* posun o 28 bitov - trieda provozu a znacka toku */
#define IP_V(ip)                (ntohl((ip)->ip_vtcfl) >> 28)

/* TCP hlavicka */
typedef u_int tcp_seq;

/* TCP hlavicka */
struct sniff_tcp {
        u_short th_sport;               /* port zdroja */
        u_short th_dport;               /* port ciela*/
        tcp_seq th_seq;                 /* sekvencia cisel */
        tcp_seq th_ack;                 /* acknowledgement cislo */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;               /* flagy TCP hlavicky */
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* okno */
        u_short th_sum;                 /* kontrolny sucet */
        u_short th_urp;                 /* urgent pointer */
};

/* handle zdroja */
extern pcap_t *handle;

/* zaciatok komunikacie */
void sniff(void);

/* hladanie HTTP header fields */
void get_my_fields(std::string text);

/* spracovanie dat */
void get_payload(const u_char *l);

/* funkcia volana pre spracovanie paketu */
void got_packet(u_char, const struct pcap_pkthdr, const u_char);

/* zaciatok komunikacie so zariadenia */
void sniff_from_device(void);

/* zaciatok komunikacie zachytenej v subore */
void sniff_from_file(void);