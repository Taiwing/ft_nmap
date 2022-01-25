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
#include <poll.h>
#include <linux/filter.h>
#include <net/ethernet.h>

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

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof(arr[0]))

#define OP_LDW (BPF_LD  | BPF_W   | BPF_ABS)
#define OP_LDH (BPF_LD  | BPF_H   | BPF_ABS)
#define OP_LDB (BPF_LD  | BPF_B   | BPF_ABS)
#define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
#define OP_RET (BPF_RET | BPF_K)

int main(int argc, char **argv)
{
	struct addrinfo	hints = { 0 }, *res = NULL;
	int				sockfd, i, ret;
	uint16_t		sport = SRC_PORT, dport = DEF_PORT;
	uint32_t		protocol = IPPROTO_TCP;

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
		else if (!strcmp(argv[i], "--icmp"))
			protocol = IPPROTO_ICMP;
		else if (!strcmp(argv[i], "--raw"))
			protocol = IPPROTO_RAW;
		else if (!strcmp(argv[i], "--ip"))
			protocol = hints.ai_family == AF_UNSPEC || AF_INET ?
				IPPROTO_IP : IPPROTO_IPV6;
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

	if ((sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
	{
		fprintf(stderr, "%s: sockfd: %s\n", argv[0], strerror(errno));
		fflush(stderr);
		freeaddrinfo(res);
		return (EXIT_FAILURE);
	}

	printf("ip: %s\n", inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr));
	struct sock_filter bpfcode_ipv4[] = {
		{ OP_LDB, 0, 0, 9		},	// ldb ip[9] (IPv4 protocol)
		{ OP_JEQ, 0, 2, 0		},	// jeq 0, fail, protocol
		{ OP_LDW, 0, 0, 12		},	// ldw ip[12] (IPv4 source address)
		{ OP_JEQ, 1, 0, 0		},	// jeq success, fail, IPv4 address
		{ OP_RET, 0, 0, 0		},	// ret #0x0 (fail)
		{ OP_RET, 0, 0, 1024	},	// ret #0xffffffff (success)
	};
	bpfcode_ipv4[1].k = protocol;
	bpfcode_ipv4[3].k = htonl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
	struct sock_fprog bpf = { ARRAY_SIZE(bpfcode_ipv4), bpfcode_ipv4 };
	if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
	{
		fprintf(stderr, "%s: setsockopt: %s\n", argv[0], strerror(errno));
		fflush(stderr);
		close(sockfd);
		freeaddrinfo(res);
		return (EXIT_FAILURE);
	}

#define	BUF_LEN		1024

	int		count = 5;
	char	buf[BUF_LEN];

#define	PFDS_COUNT	1
	struct pollfd	pfds[PFDS_COUNT] = {
		[0] = { .fd = sockfd, .events = POLLIN },
	};

	while (count)
	{
		if (!poll(pfds, PFDS_COUNT, 0))
			continue ;
		printf("events: %s%s%s%s\n",
			(pfds[0].revents & POLLIN)  ? "POLLIN "  : "",
			(pfds[0].revents & POLLHUP) ? "POLLHUP " : "",
			(pfds[0].revents & POLLERR) ? "POLLERR " : "",
			(pfds[0].revents & POLLNVAL) ? "POLLNVAL " : "");
		if (!(pfds[0].revents & POLLIN))
			fprintf(stderr, "%s: Unexpected event occured: %d\n",
					argv[0], pfds[0].revents);
		else if ((ret = recv(sockfd, buf, BUF_LEN, MSG_DONTWAIT)) < 0)
		{
			fprintf(stderr, "%s: recv: %s\n", argv[0], strerror(errno));
			break ;
		}
		else if (ret > 0)
		{
			printf("size of received packet: %d bytes\n", ret);
			print_packet(buf, res->ai_family, (size_t)ret, argv[0]);
			if (pfds[0].revents & POLLIN) --count;
		}
	}

	close(sockfd);
	freeaddrinfo(res);
	printf("Done! :)\n");
	return (EXIT_SUCCESS);
}
