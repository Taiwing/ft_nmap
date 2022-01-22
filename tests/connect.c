#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/icmpv6.h>
#include <arpa/inet.h>

#define	DEF_PORT	80
#define	SRC_PORT	45654

#define	IP_HEADER_ICMP		0x01
#define	IP_HEADER_TCP		0x06
#define	IP_HEADER_UDP		0x11
#define	IP_HEADER_ICMP6		0x3a

void			print_udphdr(struct udphdr *udph);
void			print_tcphdr(struct tcphdr *tcph);
int				print_nexthdr(void *iphdr, int domain,
					uint16_t size, char *exec);
int				print_icmphdr(void *icmph, int domain,
					uint16_t size, char *exec);
int				print_packet(void *packet, int domain,
					size_t size, char *exec);

int					print_iphdr(void *iphdr, int domain, char *exec)
{
	void			*sptr, *dptr;
	char			ipsrc[INET6_ADDRSTRLEN + 1] = { 0 };
	char			ipdst[INET6_ADDRSTRLEN + 1] = { 0 };
	struct iphdr	*ip4h = domain == AF_INET ? iphdr : NULL;
	struct ipv6hdr	*ip6h = domain == AF_INET6 ? iphdr : NULL;

	if (!ip4h && !ip6h)
		return (!!dprintf(2, "%s: %s: invalid domain '%d'\n",
			exec, __func__, domain));
	sptr = ip4h ? (void *)&ip4h->saddr : (void *)&ip6h->saddr;
	dptr = ip4h ? (void *)&ip4h->daddr : (void *)&ip6h->daddr;
	if (!inet_ntop(domain, sptr, ipsrc, INET6_ADDRSTRLEN))
		return (!!dprintf(2, "%s: inet_ntop: %s\n", exec, strerror(errno)));
	if (!inet_ntop(domain, dptr, ipdst, INET6_ADDRSTRLEN))
		return (!!dprintf(2, "%s: inet_ntop: %s\n", exec, strerror(errno)));
	printf("IPv%d header: (size = %zu)\n\t%s: %d\n\t%s: %hhu\n\t%s: %hhu\n",
		ip4h ? 4 : 6, ip4h ? sizeof(struct iphdr): sizeof(struct ipv6hdr),
		ip4h ? "tot_len" : "payload_len", ip4h ? ntohs(ip4h->tot_len) :
		ntohs(ip6h->payload_len), ip4h ? "ttl" : "hop_limit", ip4h ? ip4h->ttl
		: ip6h->hop_limit, ip4h ? "protocol" : "nexthdr", ip4h ? ip4h->protocol
		: ip6h->nexthdr);
	printf("\tsource ip: %s\n\tdestination ip: %s\n", ipsrc, ipdst);
	return (0);
}

void			print_udphdr(struct udphdr *udph)
{
	printf("UDP header: (size = %zu)\n", sizeof(struct udphdr));
	printf("\tsource port: %d\n", ntohs(udph->uh_sport));
	printf("\tdestination port: %d\n", ntohs(udph->uh_dport));
	printf("\tlen: %d\n", ntohs(udph->uh_ulen));
	printf("\tsum: %#hx\n", udph->uh_sum);
}

void			print_tcphdr(struct tcphdr *tcph)
{
	printf("TCP header: (size = %zu)\n", sizeof(struct tcphdr));
	printf("\tsource port: %d\n", ntohs(tcph->th_sport));
	printf("\tdestination port: %d\n", ntohs(tcph->th_dport));
	printf("\tsequence: %d\n", ntohl(tcph->th_seq));
	printf("\tacknowledgment: %d\n", ntohl(tcph->th_ack));
	printf("\tdata offset: %d\n", ntohs(tcph->th_off));
	printf("\tflags:");
	if (!tcph->th_flags)
		printf(" 0");
	if (tcph->th_flags & TH_FIN)
		printf(" FIN");
	if (tcph->th_flags & TH_SYN)
		printf(" SYN");
	if (tcph->th_flags & TH_RST)
		printf(" RST");
	if (tcph->th_flags & TH_PUSH)
		printf(" PSH");
	if (tcph->th_flags & TH_ACK)
		printf(" ACK");
	if (tcph->th_flags & TH_URG)
		printf(" URG");
	printf("\n\twindow: %d\n", ntohs(tcph->th_win));
	printf("\turgent pointer: %d\n", ntohs(tcph->th_urp));
	printf("\tsum: %#hx\n", tcph->th_sum);
}

int					print_nexthdr(void *iphdr, int domain,
						uint16_t size, char *exec)
{
	struct iphdr	*ip4h = domain == AF_INET ? iphdr : NULL;
	struct ipv6hdr	*ip6h = domain == AF_INET6 ? iphdr : NULL;
	int				type = ip4h ? ip4h->protocol : ip6h ? ip6h->nexthdr : 0;
	void			*nexthdr = iphdr + (ip4h ? sizeof(struct iphdr)
		: ip6h ? sizeof(struct ipv6hdr) : 0);
	uint16_t		nexthdr_size =
		type == IP_HEADER_ICMP ? sizeof(struct icmphdr) :
		type == IP_HEADER_ICMP6 ? sizeof(struct icmp6hdr) :
		type == IP_HEADER_TCP ? sizeof(struct tcphdr) :
		type == IP_HEADER_UDP ? sizeof(struct udphdr) : 0;

	if (!ip4h && !ip6h)
		return (!!dprintf(2, "%s: %s: invalid domain '%d'\n",
			exec, __func__, domain));
	if (size < nexthdr_size)
		return (!!dprintf(2, "%s: %s: too small for next header '%d'\n",
			exec, __func__, type));
	size -= nexthdr_size;
	if (type == IP_HEADER_ICMP || type == IP_HEADER_ICMP6)
		return (print_icmphdr(nexthdr, domain, size, exec));
	else if (type == IP_HEADER_TCP)
		print_tcphdr((struct tcphdr *)nexthdr);
	else if (type == IP_HEADER_UDP)
		print_udphdr((struct udphdr *)nexthdr);
	if (size)
		printf("\tdata: %hu bytes\n", size);
	return (0);
}

int					print_icmphdr(void *icmph, int domain,
						uint16_t size, char *exec)
{
	struct icmphdr	*ptr = (struct icmphdr *)icmph;
	struct iphdr	*ip4h;
	struct ipv6hdr	*ip6h;

	ip4h = domain == AF_INET ? icmph + sizeof(struct icmphdr): NULL;
	ip6h = domain == AF_INET6 ? icmph + sizeof(struct icmp6hdr) : NULL;
	if (!ip4h && !ip6h)
		return (!!dprintf(2, "%s: %s: invalid domain '%d'\n",
			exec, __func__, domain));
	printf("ICMP%s header: (size = %zu)\n", ip4h ? "" : "v6",
		ip4h ? sizeof(struct icmphdr) : sizeof(struct icmp6hdr));
	printf("\ttype: %hhu\n", ptr->type);
	printf("\tcode: %hhu\n", ptr->code);
	printf("\tchecksum: %#hx\n", ptr->checksum);
	if ((ip4h && size < sizeof(struct iphdr))
		|| (ip6h && size < sizeof(struct ipv6hdr)))
		return (!printf("\tdata: %hu bytes\n", size));
	print_iphdr(ip4h ? (void *)ip4h : (void *)ip6h, domain, exec);
	size -= ip4h ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	return (print_nexthdr(ip4h ? (void *)ip4h : (void *)ip6h,
		domain, size, exec));
}

int					print_packet(void *packet, int domain,
						size_t size, char *exec)
{
	size_t iphdr_size = domain == AF_INET ?
		sizeof(struct iphdr) : sizeof(struct ipv6hdr);

	if (size < iphdr_size)
		return (!!dprintf(2, "%s: packet is too small for an IP header\n",
			__func__));
	if (print_iphdr(packet, domain, exec))
		return (1);
	size -= iphdr_size;
	return (print_nexthdr(packet, domain, size, exec));
}

uint32_t	sum_bit16(uint16_t *data, size_t sz)
{
	uint32_t		sum;

	for (sum = 0; sz >= sizeof(uint16_t); sz -= sizeof(uint16_t))
		sum += *data++;
	if (sz)
		sum += *((uint8_t *)data);
	return (sum);
}

uint16_t	checksum(uint16_t *data, size_t sz)
{
	uint32_t	sum;

	sum = sum_bit16(data, sz);
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ((uint16_t)~sum);
}

/*
** transport_checksum: computes udp/tcp checksum
*/
int			transport_checksum(int version, void *iphdr,
	uint8_t *packet, uint16_t len)
{
	uint64_t		sum = 0;
	struct iphdr	*ip4h = version == 4 ? iphdr : NULL;
	struct ipv6hdr	*ip6h = version == 6 ? iphdr : NULL;

	if (ip4h)
		sum += sum_bit16((uint16_t *)&ip4h->saddr, sizeof(struct in_addr) * 2);
	else
		sum += sum_bit16((uint16_t *)&ip6h->saddr, sizeof(struct in6_addr) * 2);
	sum += htons(len) + htons(ip4h ? ip4h->protocol : ip6h->nexthdr)
		+ sum_bit16((uint16_t *)packet, len);
	return (checksum((uint16_t *)&sum, sizeof(uint64_t)));
}

int main(int argc, char **argv)
{
	struct addrinfo	hints = { 0 }, *res = NULL;
	int				sockfd, i, ret, protocol = IPPROTO_TCP;
	uint16_t		sport = SRC_PORT, dport = DEF_PORT;

	hints.ai_family = AF_UNSPEC;
	for (i = 1; i < argc && argv[i][0] == '-'; ++i)
	{
		if (!strcmp(argv[i], "--ipv6") || !strcmp(argv[i], "-6"))
			hints.ai_family = AF_INET6;
		else if (!strcmp(argv[i], "--ipv4") || !strcmp(argv[i], "-4"))
			hints.ai_family = AF_INET;
		else if (!strcmp(argv[i], "--udp"))
			protocol = IPPROTO_UDP;
		else if (!strcmp(argv[i], "--tcp"))
			protocol = IPPROTO_TCP;
		else if (!strncmp(argv[i], "-d", 2))
			dport = (uint16_t)atoi(argv[i] + 2);
		else if (!strncmp(argv[i], "--dport", 7))
			dport = (uint16_t)atoi(argv[i] + 7);
		else if (!strncmp(argv[i], "-s", 2))
			sport = (uint16_t)atoi(argv[i] + 2);
		else if (!strncmp(argv[i], "--sport", 7))
			sport = (uint16_t)atoi(argv[i] + 7);
	}
	if (!argv[i])
	{
		fprintf(stderr, "%s: give me an address plz :(\n", argv[0]);
		fflush(stderr);
		return (EXIT_FAILURE);
	}

	if ((ret = getaddrinfo(argv[i], NULL, &hints, &res)))
	{
		fprintf(stderr, "%s: getaddrinfo: %s\n", argv[0], gai_strerror(ret));
		fflush(stderr);
		return (EXIT_FAILURE);
	}

	if ((sockfd = socket(res->ai_family, SOCK_RAW, protocol)) < 0)
	{
		fprintf(stderr, "%s: sockfd: %s\n", argv[0], strerror(errno));
		fflush(stderr);
		freeaddrinfo(res);
		return (EXIT_FAILURE);
	}

	int ipproto = res->ai_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
	int hdrincl = res->ai_family == AF_INET ? IP_HDRINCL: IPV6_HDRINCL;
	int one = 1;
	if (setsockopt(sockfd, ipproto, hdrincl, &one, sizeof(int)) < 0)
	{
		fprintf(stderr, "%s: setsockopt: %s\n", argv[0], strerror(errno));
		fflush(stderr);
		close(sockfd);
		freeaddrinfo(res);
		return (EXIT_FAILURE);
	}

	if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0)
	{
		fprintf(stderr, "%s: connect: %s\n", argv[0], strerror(errno));
		fflush(stderr);
		close(sockfd);
		freeaddrinfo(res);
		return (EXIT_FAILURE);
	}

	struct iphdr	v4 = {
		.ihl = 5,
		.version = 4,
		.ttl = 255,
		.tot_len = sizeof(struct iphdr) + (protocol == IPPROTO_TCP ?
			sizeof(struct tcphdr) : sizeof(struct udphdr)),
		.protocol = protocol,
	};
	v4.tot_len = htons(v4.tot_len);
	struct ipv6hdr	v6 = {
		.version = 6,
		.hop_limit = 255,
		.payload_len = (protocol == IPPROTO_TCP ?
			sizeof(struct tcphdr) : sizeof(struct udphdr)),
		.nexthdr = protocol,
	};
	v6.payload_len = htons(v6.payload_len);
	struct tcphdr	*tptr, tcph = {
		.th_sport = htons(sport),
		.th_dport = htons(dport),
		.th_seq = htonl(0x12344321),
		.th_ack = htonl(0),
		.th_off = sizeof(struct tcphdr) / sizeof(uint32_t),
		.th_flags = TH_SYN,
		.th_win = htons(0xfff),
		.th_urp = htons(0),
	};
	struct udphdr	*uptr, udph = {
		.uh_sport = htons(sport),
		.uh_dport = htons(dport),
		.uh_ulen = htons(sizeof(struct udphdr)),
	};
	uint8_t		packet[sizeof(struct ipv6hdr) + sizeof(struct tcphdr)] = { 0 };
	uint16_t	size = 0;

	if (res->ai_family == AF_INET)
	{
		size = ntohs(v4.tot_len);
		memcpy(packet, &v4, sizeof(v4));
		if (protocol == IPPROTO_TCP)
		{
			memcpy(packet + sizeof(v4), &tcph, sizeof(tcph));
			tptr = (struct tcphdr *)packet + sizeof(v4);
			tptr->th_sum = transport_checksum(4, packet, (uint8_t *)tptr, size - sizeof(v4));
		}
		else
		{
			memcpy(packet + sizeof(v4), &udph, sizeof(udph));
			uptr = (struct udphdr *)packet + sizeof(v4);
			uptr->uh_sum = transport_checksum(4, packet, (uint8_t *)uptr, size - sizeof(v4));
		}
	}
	else
	{
		size = sizeof(v6) + ntohs(v6.payload_len);
		memcpy(packet, &v6, sizeof(v6));
		if (protocol == IPPROTO_TCP)
		{
			memcpy(packet + sizeof(v6), &tcph, sizeof(tcph));
			tptr = (struct tcphdr *)packet + sizeof(v6);
			tptr->th_sum = transport_checksum(6, packet, (uint8_t *)tptr, size - sizeof(v6));
		}
		else
		{
			memcpy(packet + sizeof(v6), &udph, sizeof(udph));
			uptr = (struct udphdr *)packet + sizeof(v6);
			uptr->uh_sum = transport_checksum(6, packet, (uint8_t *)uptr, size - sizeof(v6));
		}
	}

	//TODO: See if we need this. I dont think this is the case because we can
	//use different sockets for the sending and for the receiving, it does not
	//matter.
	/*
	if (sendto(sockfd, packet, size, 0, res->ai_addr, res->ai_addrlen) < 0)
	{
		fprintf(stderr, "%s: sendto: %s\n", argv[0], strerror(errno));
		fflush(stderr);
		close(sockfd);
		freeaddrinfo(res);
		return (EXIT_FAILURE);
	}
	*/

#define	BUF_LEN	1024

	//TODO: Check if can set a port for the listening part. Maybe with the bind
	//function ? Or by setting the port when opening socket ? TBD...
	//
	//But even if we cant, it already works basically, although it would have to
	//check every incoming packets from an host, not only the ones from the port
	//we are scanning. This might not be a problem at all though... This could
	//be very useful to scan multiple ports at the same time actually. Pretty
	//good stuff when you think about it.
	//
	//Also see if we can receive UDP and ICMP packets, otherwise it's going to
	//be difficult to use this for nmap.
	int		count = 5;
	char	buf[BUF_LEN];
	while (count)
	{
		if ((ret = recv(sockfd, buf, BUF_LEN, MSG_DONTWAIT)) < 0)
			continue ;
		printf("size of received packet: %d bytes\n", ret);
		print_packet(buf, res->ai_family, (size_t)ret, argv[0]);
		--count;
	}

	close(sockfd);
	freeaddrinfo(res);
	printf("Done! :)\n");
	return (EXIT_SUCCESS);
}
