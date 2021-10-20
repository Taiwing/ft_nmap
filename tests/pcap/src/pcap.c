/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/05 05:03:01 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 09:24:38 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/ip_icmp.h>
#include <linux/icmpv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ifaddrs.h>

static int			get_network(char *prog, char **dev, char *net, char *mask,
		bpf_u_int32 *netpp)
{
	int				ret;
	char			*ptr;
	struct in_addr	addr;
	bpf_u_int32		netp;
	bpf_u_int32		maskp;
	char			errbuf[PCAP_ERRBUF_SIZE];

	if (!(*dev = pcap_lookupdev(errbuf)))
	{
		dprintf(2, "%s: pcap_lookupdev: %s\n", prog, errbuf);
		return (EXIT_FAILURE);
	}
	if ((ret = pcap_lookupnet(*dev, &netp, &maskp, errbuf)) < 0)
	{
		dprintf(2, "%s: pcap_lookupnet: %s\n", prog, errbuf);
		return (EXIT_FAILURE);
	}
	addr.s_addr = netp;
	if (!(ptr = inet_ntoa(addr)))
	{
		dprintf(2, "%s: inet_ntoa: error\n", prog);
		return (EXIT_FAILURE);
	}
	strncpy(net, ptr, INET6_ADDRSTRLEN);
	addr.s_addr = maskp;
	if (!(ptr = inet_ntoa(addr)))
	{
		dprintf(2, "%s: inet_ntoa: error\n", prog);
		return (EXIT_FAILURE);
	}
	strncpy(mask, ptr, INET6_ADDRSTRLEN);
	*netpp = netp;
	return (EXIT_SUCCESS);
}

#define MAX_HEADER_SIZE	\
	(sizeof(struct ether_header) + sizeof(struct ipv6hdr)\
	+ sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr)\
	+ sizeof(struct tcphdr))

static pcap_t		*open_device(char *prog, char *dev)
{
	pcap_t	*descr;
	char	errbuf[PCAP_ERRBUF_SIZE];

	//if (!(descr = pcap_open_live(dev, BUFSIZ, 0, 1000000, errbuf)))
	if (!(descr = pcap_open_live(dev, 100, 0, 1, errbuf)))
		dprintf(2, "%s: pcap_open_live: %s\n", prog, errbuf);
	return (descr);
}

static void	phandler(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{
	//TEMP
	write(1, ".", 1);
	//TEMP
	memcpy(user, h, sizeof(struct pcap_pkthdr));
	memcpy(user + sizeof(struct pcap_pkthdr), bytes, h->len);
}

#define PACKET_SIZE_MAX	(sizeof(struct pcap_pkthdr) + 1024)

static int			grab_packet(char *prog, pcap_t *descr, u_char *packet)
{
	int						ret;
	struct pcap_pkthdr		*h;
	u_char					buf[PACKET_SIZE_MAX];

	//if ((ret = pcap_dispatch(descr, 1, phandler, buf)) == PCAP_ERROR)
	if ((ret = pcap_dispatch(descr, 0, phandler, buf)) == PCAP_ERROR)
	{
		dprintf(2, "%s: pcap_dispatch: did not grab packet :(\n", prog);
		return (1);
	}
	else if (ret == PCAP_ERROR_BREAK)
	{
		dprintf(2, "%s: pcap_dispatch: loop has been broken\n", prog);
		return (1);
	}
	h = (struct pcap_pkthdr *)buf;
	memcpy(packet, buf + sizeof(struct pcap_pkthdr), h->len);
	printf("\nGrabbed packet of length %d\n", h->len);
	printf("Received at .... %s\n", ctime((const time_t *)&h->ts.tv_sec));
	printf("Ethernet address length is %d\n", ETHER_HDR_LEN);
	return (0);
}

static void			print_mac(u_char *ptr)
{
	for (int i = 0; i < ETHER_ADDR_LEN; ++i)
		printf("%02x%c", *ptr++, i < ETHER_ADDR_LEN - 1 ? ':' : '\n');
}

static int			print_ether_type(int *type, u_char *packet)
{
	struct ether_header	*eptr = (struct ether_header *)packet;

	*type = ntohs(eptr->ether_type);
	printf("Ethernet type hex:%x dec:%d %s\n", *type, *type,
		*type == ETHERTYPE_IP ? "is an IP packet" :
		*type == ETHERTYPE_IPV6 ? "is an IPv6 packet" :
		*type == ETHERTYPE_ARP ? "is an ARP packet" :
		"not IP");
	printf("Destination Address: ");
	print_mac((u_char *)eptr->ether_dhost);
	printf("Source Address: ");
	print_mac((u_char *)eptr->ether_shost);
	return (*type != ETHERTYPE_IP
			&& *type != ETHERTYPE_IPV6
			&& *type != ETHERTYPE_ARP);
}

int					print_iphdr(void *iphdr, int domain, char *prog)
{
	void			*sptr, *dptr;
	char			ipsrc[INET6_ADDRSTRLEN + 1] = { 0 };
	char			ipdst[INET6_ADDRSTRLEN + 1] = { 0 };
	struct iphdr	*ip4h = domain == AF_INET ? iphdr : NULL;
	struct ipv6hdr	*ip6h = domain == AF_INET6 ? iphdr : NULL;

	if (!ip4h && !ip6h)
		return (!!dprintf(2, "%s: %s: invalid domain '%d'\n",
			prog, __func__, domain));
	sptr = ip4h ? (void *)&ip4h->saddr : (void *)&ip6h->saddr;
	dptr = ip4h ? (void *)&ip4h->daddr : (void *)&ip6h->daddr;
	if (!inet_ntop(domain, sptr, ipsrc, INET6_ADDRSTRLEN))
		return (!!dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno)));
	if (!inet_ntop(domain, dptr, ipdst, INET6_ADDRSTRLEN))
		return (!!dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno)));
	printf("IPv%d header: (size = %zu)\n%s: %d\n%s: %hhu\n%s: %hhu\n", ip4h ?
		4 : 6, ip4h ? sizeof(struct iphdr): sizeof(struct ipv6hdr), ip4h ?
		"tot_len" : "payload_len", ip4h ? ntohs(ip4h->tot_len) :
		ntohs(ip6h->payload_len), ip4h ? "ttl" : "hop_limit", ip4h ? ip4h->ttl
		: ip6h->hop_limit, ip4h ? "protocol" : "nexthdr", ip4h ? ip4h->protocol
		: ip6h->nexthdr);
	printf("source ip: %s\ndestination ip: %s\n", ipsrc, ipdst);
	return (0);
}

void			print_udphdr(struct udphdr *udph)
{
	printf("UDP header: (size = %zu)\n", sizeof(struct udphdr));
	printf("source port: %d\n", ntohs(udph->uh_sport));
	printf("destination port: %d\n", ntohs(udph->uh_dport));
	printf("len: %d\n", ntohs(udph->uh_ulen));
	printf("sum: %#hx\n", udph->uh_sum);
}

int					get_ips(struct sockaddr_in *ipv4, struct sockaddr_in6 *ipv6,
	char *dev, char *prog)
{
	struct ifaddrs	*ifap = NULL, *ifap_too = NULL;
	int				v4 = 0, v6 = 0;

	if (getifaddrs(&ifap) < 0)
	{
		dprintf(2, "%s: getifaddrs: %s\n", prog, strerror(errno));
		return (-1);
	}
	ifap_too = ifap;
	for (; ifap && (!v4 || !v6); ifap = ifap->ifa_next)
	{
		if (ifap->ifa_name && !strcmp(dev, ifap->ifa_name) && ifap->ifa_addr)
		{
			if (!v4 && ifap->ifa_addr->sa_family == AF_INET)
			{
				v4 = 1;
				memcpy(ipv4, ifap->ifa_addr, sizeof(struct sockaddr_in));
			}
			else if (!v6 && ifap->ifa_addr->sa_family == AF_INET6)
			{
				v6 = 2;
				memcpy(ipv6, ifap->ifa_addr, sizeof(struct sockaddr_in6));
			}
		}
	}
	freeifaddrs(ifap_too); //TODO: put in clean ft_atexit handler
	return (v4 + v6);
}

int					print_ips(int ip, char *ip4, char *ip6,
	struct sockaddr_in *ipv4, struct sockaddr_in6 *ipv6, char *prog, char *dev)
{
	if (!ip)
	{
		dprintf(2, "%s: get_ips: no valid ip for %s interface\n", prog, dev);
		return (EXIT_FAILURE);
	}
	if (ip & 0x01)
	{
		if (!inet_ntop(AF_INET, &ipv4->sin_addr, ip4, INET6_ADDRSTRLEN))
		{
			dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
			return (1);
		}
		printf("ipv4: %s\n", ip4);
	}
	if (ip & 0x02)
	{
		if (!inet_ntop(AF_INET6, &ipv6->sin6_addr, ip6, INET6_ADDRSTRLEN))
		{
			dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
			return (1);
		}
		printf("ipv6: %s\n", ip6);
	}
	return (0);
}

#define FILTER_MAXLEN	1024

int					set_filter(pcap_t *descr, int ip, char *ip4, char *ip6,
		char *user_filter, char *prog, bpf_u_int32 netp)
{
	char				filter[FILTER_MAXLEN] = { 0 };
	struct bpf_program	fp = { 0 };

	strncat(filter, "(dst host ", INET6_ADDRSTRLEN);
	if (ip & 1)
		strncat(filter, ip4, INET6_ADDRSTRLEN);
	if (ip == 3)
		strncat(filter, " || dst host ", INET6_ADDRSTRLEN);
	if (ip & 2)
		strncat(filter, ip6, INET6_ADDRSTRLEN);
	strncat(filter, ")", INET6_ADDRSTRLEN);
	if (user_filter)
	{
		strncat(filter, " && (", INET6_ADDRSTRLEN);
		strncat(filter, user_filter, INET6_ADDRSTRLEN);
		strncat(filter, ")", INET6_ADDRSTRLEN);
	}
	if (pcap_compile(descr, &fp, filter, 1, netp) == PCAP_ERROR)
	{
		dprintf(2, "%s: pcap_compile: %s\n", prog, pcap_geterr(descr));
		return (1);
	}
	printf("pcap filter: %s\n", filter);
	if (pcap_setfilter(descr, &fp) == PCAP_ERROR)
	{
		dprintf(2, "%s: pcap_setfilter: %s\n", prog, pcap_geterr(descr));
		return (1);
	}
	pcap_freecode(&fp); //TODO: put in clean ft_atexit handler
	return (0);
}


int	init_socket(int domain, int protocol, char *prog)
{
	int	sfd, one, ret;

	one = 1;
	if ((sfd = socket(domain, SOCK_RAW, protocol)) < 0)
	{
		dprintf(2, "%s: socket: %s\n", prog, strerror(errno));
		return (-1);
	}
	ret = -2;
	if (domain == AF_INET)
		ret = setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int));
	else if (domain == AF_INET6)
		ret = setsockopt(sfd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(int));
	if (ret == -2)
		dprintf(2, "%s: %s: domain must be AF_INET or AF_INET6\n",
			prog, __func__);
	else if (ret < 0)
		dprintf(2, "%s: setsockopt: %s\n", prog, strerror(errno));
	if (ret < 0)
	{
		close(sfd);
		return (ret);
	}
	return (sfd);
}

# define IP_HEADER_ICMP	0x01
# define IP_HEADER_TCP	0x06
# define IP_HEADER_UDP	0x11

typedef struct		s_iph_args
{
	uint8_t			version;
	struct sockaddr	*dstip;
	struct sockaddr	*srcip;
	uint16_t		protocol;
	uint8_t			hop_limit;
	uint16_t		layer5_len;
}					t_iph_args;

static void	init_ipv4_header(struct iphdr *ip, t_iph_args *args)
{
	struct sockaddr_in	*ptr;

	bzero(ip, sizeof(struct iphdr));
	ip->ihl = 5;
	ip->version = args->version;
	ip->ttl = args->hop_limit;
	ptr = (struct sockaddr_in *)args->srcip;
	memcpy(&ip->saddr, &ptr->sin_addr, sizeof(struct in_addr));
	ptr = (struct sockaddr_in *)args->dstip;
	memcpy(&ip->daddr, &ptr->sin_addr, sizeof(struct in_addr));
	ip->tot_len = args->layer5_len + sizeof(struct iphdr);
	ip->protocol = args->protocol;
	if (ip->protocol == IP_HEADER_ICMP)
		ip->tot_len += sizeof(struct icmphdr);
	else if (ip->protocol == IP_HEADER_TCP)
		ip->tot_len += sizeof(struct tcphdr);
	else if (ip->protocol == IP_HEADER_UDP)
		ip->tot_len += sizeof(struct udphdr);
	ip->tot_len = htons(ip->tot_len);
}

static void	init_ipv6_header(struct ipv6hdr *ip, t_iph_args *args)
{
	struct sockaddr_in6	*ptr;

	bzero(ip, sizeof(struct ipv6hdr));
	ip->version = args->version;
	ip->hop_limit = args->hop_limit;
	ptr = (struct sockaddr_in6 *)args->srcip;
	memcpy(&ip->saddr, &ptr->sin6_addr, sizeof(struct in6_addr));
	ptr = (struct sockaddr_in6 *)args->dstip;
	memcpy(&ip->daddr, &ptr->sin6_addr, sizeof(struct in6_addr));
	ip->payload_len = args->layer5_len;
	ip->nexthdr = args->protocol;
	if (ip->nexthdr == IP_HEADER_ICMP)
		ip->payload_len += sizeof(struct icmp6hdr);
	else if (ip->nexthdr == IP_HEADER_TCP)
		ip->payload_len += sizeof(struct tcphdr);
	else if (ip->nexthdr == IP_HEADER_UDP)
		ip->payload_len += sizeof(struct udphdr);
	ip->payload_len = htons(ip->payload_len);
}

int		init_ip_header(void *ipptr, t_iph_args *args)
{
	if ((args->version != 4 && args->version != 6)
		|| !args->dstip || !args->srcip)
		return (1);
	if (args->version == 4)
		init_ipv4_header((struct iphdr *)ipptr, args);
	else
		init_ipv6_header((struct ipv6hdr *)ipptr, args);
	return (0);
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
** udp_checksum: sets length and computes and sets udp checksum
*/
int			udp_checksum(int version, void *iphdr,
	uint8_t *udp_packet, uint16_t len)
{
	uint64_t		sum = 0;
	struct udphdr	*udph = (struct udphdr *)udp_packet;
	struct iphdr	*ip4h = version == 4 ? iphdr : NULL;
	struct ipv6hdr	*ip6h = version == 6 ? iphdr : NULL;

	if (len < sizeof(struct udphdr) || (!ip4h && !ip6h))
		return (-1);
	if (ip4h)
		sum += sum_bit16((uint16_t *)&ip4h->saddr, sizeof(struct in_addr) * 2);
	else if (ip6h)
		sum += sum_bit16((uint16_t *)&ip6h->saddr, sizeof(struct in6_addr) * 2);
	udph->uh_sum = 0;
	udph->uh_ulen = htons(len);
	sum += udph->uh_ulen + htons(IP_HEADER_UDP)
		+ sum_bit16((uint16_t *)udp_packet, len);
	udph->uh_sum = checksum((uint16_t *)&sum, sizeof(uint64_t));
	return (0);
}

/*
** init_udp_header:
**
** Writes entire udp header from scatch. Needs an ip header with version
** byte, total or payload length, source address and destination address.
**
** The udp header is written on the first sizeof(struct udphdr) bytes of
** udp_packet, which is supposed to be followed by the udp payload data
** if it has any. The length of the udp_packet is given by the ip header
** length field.
*/
int			init_udp_header(uint8_t *udp_packet, void *iphdr,
	uint16_t srcp, uint16_t dstp)
{
	struct udphdr	*udph = (struct udphdr *)udp_packet;
	uint8_t			version = (*(uint8_t *)iphdr) >> 4;
	struct iphdr	*ip4h = version == 4 ? iphdr : NULL;
	struct ipv6hdr	*ip6h = version == 6 ? iphdr : NULL;
	uint16_t		udplen = ip6h ? ntohs(ip6h->payload_len)
						: ip4h ? ntohs(ip4h->tot_len) : 0;

	if (ip4h)
		udplen = udplen > sizeof(struct iphdr)
			? udplen - sizeof(struct iphdr) : 0;
	if ((!ip4h && !ip6h) || udplen < sizeof(struct udphdr))
		return (-1);
	udph->uh_sport = htons(srcp);
	udph->uh_dport = htons(dstp);
	return (udp_checksum(version, iphdr, udp_packet, udplen));
}

/*
** init_tcp_header:
**
** Writes entire tcp header from scatch. Needs an ip header with version
** byte, total or payload length, source address and destination address.
**
** The tcp header is written on the first sizeof(struct tcphdr) bytes of
** tcp_packet, which is supposed to be followed by the tcp payload data
** if it has any. The length of the tcp_packet is given by the ip header
** length field.
*/
int			init_tcp_header(uint8_t *tcp_packet, void *iphdr,
	uint16_t srcp, uint16_t dstp)
{
	struct tcphdr	*tcph = (struct tcphdr *)tcp_packet;
	uint8_t			version = (*(uint8_t *)iphdr) >> 4;
	struct iphdr	*ip4h = version == 4 ? iphdr : NULL;
	struct ipv6hdr	*ip6h = version == 6 ? iphdr : NULL;
	uint16_t		tcplen = ip6h ? ntohs(ip6h->payload_len)
						: ip4h ? ntohs(ip4h->tot_len) : 0;

	if (ip4h)
		tcplen = tcplen > sizeof(struct iphdr)
			? tcplen - sizeof(struct iphdr) : 0;
	if ((!ip4h && !ip6h) || tcplen < sizeof(struct tcphdr))
		return (-1);
	tcph->th_sport = htons(srcp);
	tcph->th_dport = htons(dstp);
	//return (tcp_checksum(version, iphdr, tcp_packet, tcplen));
	return (0);
}

#define PORT_DEF	45654

int					main(int argc, char **argv)
{
	struct iphdr		iphdr;
	struct ipv6hdr		ipv6hdr;
	pcap_t				*descr;
	int					type, ip;
	struct sockaddr_in	srcip_v4 = { 0 };
	struct sockaddr_in6	srcip_v6 = { 0 };
	struct sockaddr_in	dstip_v4 = { 0 };
	struct sockaddr_in6	dstip_v6 = { 0 };
	u_char				packet[PACKET_SIZE_MAX] = { 0 };
	char				*dev, net[INET6_ADDRSTRLEN], mask[INET6_ADDRSTRLEN];
	char				ip4[INET6_ADDRSTRLEN] = { 0 },
						ip6[INET6_ADDRSTRLEN] = { 0 };
	bpf_u_int32			netp;

	char				*prog = argv[0];
	char				*user_filter = NULL;
	char				*user_dstip_v4 = NULL;
	char				*user_dstip_v6 = NULL;
	char				*user_srcip_v4 = NULL;
	char				*user_srcip_v6 = NULL;
	char				*user_sport = NULL;
	char				*user_dport = NULL;
	for (int i = 1; i < argc; ++i)
	{
		if (!strcmp(argv[i], "--filter"))
			user_filter = argv[++i];
		else if (!strcmp(argv[i], "--dstip_v4"))
			user_dstip_v4 = argv[++i];
		else if (!strcmp(argv[i], "--dstip_v6"))
			user_dstip_v6 = argv[++i];
		else if (!strcmp(argv[i], "--srcip_v4"))
			user_srcip_v4 = argv[++i];
		else if (!strcmp(argv[i], "--srcip_v6"))
			user_srcip_v6 = argv[++i];
		else if (!strcmp(argv[i], "--sport"))
			user_sport = argv[++i];
		else if (!strcmp(argv[i], "--dport"))
			user_dport = argv[++i];
	}

	/*
	printf("sizes:\n");
	printf("ether_header: %zu\n", sizeof(struct ether_header));
	printf("iphdr: %zu\n", sizeof(struct iphdr));
	printf("ipv6hdr: %zu\n", sizeof(struct ipv6hdr));
	printf("icmphdr: %zu\n", sizeof(struct icmphdr));
	printf("icmp6hdr: %zu\n", sizeof(struct icmp6hdr));
	printf("tcphdr: %zu\n", sizeof(struct tcphdr));
	printf("udphdr: %zu\n", sizeof(struct udphdr));
	printf("MAX_HEADER_SIZE: %zu\n\n", MAX_HEADER_SIZE);
	*/

	printf("---- Network ----\n");
	if (get_network(prog, &dev, net, mask, &netp))
		return (EXIT_FAILURE);
	printf("dev: %s\n", dev);
	printf("net: %s\n", net);
	printf("mask: %s\n", mask);
	if ((ip = get_ips(&srcip_v4, &srcip_v6, dev, prog)) < 0)
		return (EXIT_FAILURE);
	if (print_ips(ip, ip4, ip6, &srcip_v4, &srcip_v6, prog, dev))
		return (EXIT_FAILURE);
	memcpy(&dstip_v4, &srcip_v4, sizeof(dstip_v4));
	memcpy(&dstip_v6, &srcip_v6, sizeof(dstip_v6));

	printf("\n---- Receive packet ----\n");
	if (!(descr = open_device(prog, dev)))
		return (EXIT_FAILURE);
	if (set_filter(descr, ip, ip4, ip6, user_filter, prog, netp))
		return (EXIT_FAILURE);
	if (grab_packet(prog, descr, packet))
		return (EXIT_FAILURE);
	if (print_ether_type(&type, packet))
		return (EXIT_FAILURE);
	if (type == ETHERTYPE_IP)
	{
		memcpy(&iphdr, packet + sizeof(struct ether_header),
			sizeof(struct iphdr));
		print_iphdr(&iphdr, AF_INET, prog);
		if (!user_dstip_v4)
			memcpy(&dstip_v4.sin_addr, &iphdr.saddr, sizeof(dstip_v4.sin_addr));
	}
	else if (type == ETHERTYPE_IPV6)
	{
		memcpy(&ipv6hdr, packet + sizeof(struct ether_header),
			sizeof(struct ipv6hdr));
		print_iphdr(&ipv6hdr, AF_INET6, prog);
		if (!user_dstip_v6)
			memcpy(&dstip_v6.sin6_addr, &ipv6hdr.saddr, sizeof(dstip_v6.sin6_addr));
	}
	pcap_close(descr);
	printf("\n");

	if (ip != 3)
	{
		dprintf(2, "%s: ipv4 and ipv6 are not both available\n", prog);
		return (EXIT_FAILURE);
	}
	uint16_t		sport = PORT_DEF, dport = PORT_DEF;
	struct iphdr	ip4h = { 0 };
	struct ipv6hdr	ip6h = { 0 };
	//struct tcphdr	tcph = { 0 };
	struct udphdr	udph = { 0 };
	int				ip4tcp_socket, ip4udp_socket, ip6tcp_socket, ip6udp_socket;
	unsigned char	ipbuf[sizeof(struct in6_addr)];
	if ((ip4tcp_socket = init_socket(AF_INET, IPPROTO_TCP, prog)) < 0)
		return (EXIT_FAILURE);
	if ((ip4udp_socket = init_socket(AF_INET, IPPROTO_UDP, prog)) < 0)
		return (EXIT_FAILURE);
	if ((ip6tcp_socket = init_socket(AF_INET6, IPPROTO_TCP, prog)) < 0)
		return (EXIT_FAILURE);
	if ((ip6udp_socket = init_socket(AF_INET6, IPPROTO_UDP, prog)) < 0)
		return (EXIT_FAILURE);
	if (user_srcip_v4 && inet_pton(AF_INET, user_srcip_v4, ipbuf) > 0)
		memcpy(&srcip_v4.sin_addr, ipbuf, sizeof(srcip_v4.sin_addr));
	if (user_srcip_v6 && inet_pton(AF_INET6, user_srcip_v6, ipbuf) > 0)
		memcpy(&srcip_v6.sin6_addr, ipbuf, sizeof(srcip_v6.sin6_addr));
	if (user_dstip_v4 && inet_pton(AF_INET, user_dstip_v4, ipbuf) > 0)
		memcpy(&dstip_v4.sin_addr, ipbuf, sizeof(dstip_v4.sin_addr));
	if (user_dstip_v6 && inet_pton(AF_INET6, user_dstip_v6, ipbuf) > 0)
		memcpy(&dstip_v6.sin6_addr, ipbuf, sizeof(dstip_v6.sin6_addr));
	if (user_sport)
		sport = atoi(user_sport);
	if (user_dport)
		dport = atoi(user_dport);

	printf("---- Send IPv4 UDP packet ----\n");
	t_iph_args	ipv4args = {
		.version = 4,
		.dstip = (struct sockaddr *)&dstip_v4,
		.srcip = (struct sockaddr *)&srcip_v4,
		.protocol = IP_HEADER_UDP,
		.hop_limit = 255,
		.layer5_len = 0,
	};
	init_ip_header(&ip4h, &ipv4args);
	print_iphdr(&ip4h, AF_INET, prog);
	bzero(packet, sizeof(packet));
	if (init_udp_header((uint8_t *)&udph, &ip4h, sport, dport) < 0)
		dprintf(2, "%s: init_udp_header: failure\n", prog);
	print_udphdr(&udph);
	memcpy(packet, &ip4h, sizeof(ip4h));
	memcpy(packet + sizeof(ip4h), &udph, sizeof(udph));
	if (sendto(ip4udp_socket, packet, ntohs(ip4h.tot_len), 0,
			(struct sockaddr *)&dstip_v4, sizeof(dstip_v4)) < 0)
		dprintf(2, "%s: sendto: %s\n", prog, strerror(errno));
	else
		printf("Status: Package Sent\n");

	printf("\n---- Send IPv6 UDP packet ----\n");
	t_iph_args	ipv6args = {
		.version = 6,
		.dstip = (struct sockaddr *)&dstip_v6,
		.srcip = (struct sockaddr *)&srcip_v6,
		.protocol = IP_HEADER_UDP,
		.hop_limit = 255,
		.layer5_len = 0,
	};
	init_ip_header(&ip6h, &ipv6args);
	print_iphdr(&ip6h, AF_INET6, prog);
	bzero(packet, sizeof(packet));
	bzero(&udph, sizeof(struct udphdr));
	if (init_udp_header((uint8_t *)&udph, &ip6h, sport, dport) < 0)
		dprintf(2, "%s: init_udp_header: failure\n", prog);
	print_udphdr(&udph);
	memcpy(packet, &ip6h, sizeof(ip6h));
	memcpy(packet + sizeof(ip6h), &udph, sizeof(udph));
	if (sendto(ip6udp_socket, packet, ntohs(ip6h.payload_len) + sizeof(ip6h), 0,
			(struct sockaddr *)&dstip_v6, sizeof(dstip_v6)) < 0)
		dprintf(2, "%s: sendto: %s\n", prog, strerror(errno));
	else
		printf("Status: Package Sent\n");
	//TODO: put in clean ft_atexit handler
	close(ip4tcp_socket);
	close(ip4udp_socket);
	close(ip6tcp_socket);
	close(ip6udp_socket);
	//TODO
	return (EXIT_SUCCESS);
}
