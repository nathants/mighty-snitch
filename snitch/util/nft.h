#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "util.h"

#define NFQ_SIZEOF_OUTPUT 1024 * 1024
#define NFQ_LINKTYPE_IPV4 12
#define NFQ_QUEUE 0
#define NFQ_QUEUE_SIZE 4096
#define NFQ_PACKET_SIZE 4096
#define NFQ_TOTAL_SIZE 4096 * 4096

#define RR_A 1
#define RR_CNAME 5

int dns_parse(unsigned char *r, int rlen, int (*callback)(unsigned char *, int, const void *, int, const void *)) { // based on musl @ 4100279825c17807bdabf1c128ba4e49a1dea406
	int qdcount, ancount;
	unsigned char *p;
	unsigned char *qname;
	int len;
	if (rlen<12) return -1;
	if ((r[3]&15)) return 0;
	p = r+12;
	qdcount = r[4]*256 + r[5];
	ancount = r[6]*256 + r[7];
	if (qdcount+ancount > 64) return -1;
	while (qdcount--) {
        int qoffset = 0; // start change to musl code. keep a pointer to the qname and pass it to the callback.
        while (1) {
            if (qoffset > rlen - (p-r)) return -1;
            if (p[qoffset] == 0) break;
            int size = p[qoffset];
            p[qoffset] = '.';
            qoffset += size + 1;
        }
        qname = p + 1; // end change to musl code.
		while (p-r < rlen && *p-1U < 127) p++;
		if (*p>193 || (*p==193 && p[1]>254) || p>r+rlen-6)
			return -1;
		p += 5 + !!*p;
	}
	while (ancount--) {
		while (p-r < rlen && *p-1U < 127) p++;
		if (*p>193 || (*p==193 && p[1]>254) || p>r+rlen-6)
			return -1;
		p += 1 + !!*p;
		len = p[8]*256 + p[9];
		if (p+len > r+rlen) return -1;
		if (callback(qname, p[1], p+10, len, r) < 0) return -1;
		p += 10 + len;
	}
	return 0;
}

typedef struct packet_s {
    char proto[5];
    char saddr[15];
    char daddr[15];
    int sport;
    int dport;
    int offset;
    int size;
} packet_t;

int parse_ipv4(unsigned char *buf, int size, packet_t *p) {
    p->offset = 0;
    struct iphdr *ip = (struct iphdr*)buf;
    p->offset += sizeof(*ip);
    if (p->offset > size)
        return -1;
    if (ip->version != 4)
        return -1;
    strcpy(p->saddr, inet_ntoa(*(struct in_addr*)&ip->saddr));
    strcpy(p->daddr, inet_ntoa(*(struct in_addr*)&ip->daddr));
    switch (ip->protocol) {
    case IPPROTO_ICMP:
        sprintf(p->proto, "icmp");
        return 0;
    case IPPROTO_TCP:
        sprintf(p->proto, "tcp");
        struct tcphdr *tcp = (struct tcphdr*)(buf + p->offset);
        p->offset += sizeof(*tcp);
        if (p->offset > size)
            return -1;
        p->sport = ntohs(tcp->th_sport);
        p->dport = ntohs(tcp->th_dport);
        return 0;
    case IPPROTO_UDP:
        sprintf(p->proto, "udp");
        struct udphdr *udp = (struct udphdr*)(buf + p->offset);
        p->offset += sizeof(*udp);
        if (p->offset > size)
            return -1;
        p->sport = ntohs(udp->uh_sport);
        p->dport = ntohs(udp->uh_dport);
        p->size = ntohs(ip->tot_len) - p->offset;
        return 0;
    default:
        sprintf(p->proto, "%d", ip->protocol);
        return 0;
    }
}

char *conf_content =
    "flush ruleset\n"
    "table ip snitch {\n"
    "	chain inbound {\n"
    "		type filter hook input priority filter; policy accept;\n"
    "		udp sport 53 counter queue num 0 bypass\n"
    "	}\n"
    "}\n";

#define CONF_FILE "/tmp/nftables.conf"

void nftables_init() {
    FILE *f = fopen(CONF_FILE, "w");
    ASSERT(strlen(conf_content) == fwrite(conf_content, 1, strlen(conf_content), f), "failed to write nftables conf to /tmp\n");
    ASSERT(0 == fclose(f), "failed to close nftables conf file\n");
    ASSERT(0 == pclose(popen("nft -f " CONF_FILE, "r")), "failed to load nft ruleset\n");
}
