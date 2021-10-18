/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/05 05:03:01 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/18 19:49:18 by yforeau          ###   ########.fr       */
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
	memcpy((void *)user, (void *)h, sizeof(struct pcap_pkthdr));
	memcpy((void *)(user + sizeof(struct pcap_pkthdr)), (void *)bytes, h->len);
}

#define PACKET_SIZE_MAX	(sizeof(struct pcap_pkthdr) + 1024)

static int			grab_packet(char *prog, pcap_t *descr, u_char *packet)
{
	int						ret;
	struct pcap_pkthdr		*h;
	u_char					buf[PACKET_SIZE_MAX];
	char					errbuf[PCAP_ERRBUF_SIZE];

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
	memcpy((void *)packet, (void *)(buf + sizeof(struct pcap_pkthdr)), h->len);
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

int					parse_iphdr(struct iphdr *iphdr, u_char *packet, char *prog)
{
	int		type;
	char	ipsrc[INET6_ADDRSTRLEN + 1] = { 0 };
	char	ipdst[INET6_ADDRSTRLEN + 1] = { 0 };

	memcpy((void *)iphdr, (void *)(packet + sizeof(struct ether_header)),
		sizeof(struct iphdr));
	if (!inet_ntop(AF_INET, (void *)&iphdr->saddr, ipsrc, INET6_ADDRSTRLEN))
	{
		dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
		return (1);
	}
	if (!inet_ntop(AF_INET, (void *)&iphdr->daddr, ipdst, INET6_ADDRSTRLEN))
	{
		dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
		return (1);
	}
	printf("IP packet: (len = %hu, iphdr_size = %zu)\n", ntohs(iphdr->tot_len),
		sizeof(struct iphdr));
	printf("source ip: %s\n", ipsrc);
	printf("destination ip: %s\n", ipdst);
	return (0);
}

int					parse_ipv6hdr(struct ipv6hdr *iphdr, u_char *packet, char *prog)
{
	int		type;
	char	ipsrc[INET6_ADDRSTRLEN + 1] = { 0 };
	char	ipdst[INET6_ADDRSTRLEN + 1] = { 0 };

	memcpy((void *)iphdr, (void *)(packet + sizeof(struct ether_header)),
		sizeof(struct ipv6hdr));
	if (!inet_ntop(AF_INET6, (void *)&iphdr->saddr, ipsrc, INET6_ADDRSTRLEN))
	{
		dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
		return (1);
	}
	if (!inet_ntop(AF_INET6, (void *)&iphdr->daddr, ipdst, INET6_ADDRSTRLEN))
	{
		dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
		return (1);
	}
	printf("IP packet: (len = %lu, iphdr_size = %zu)\n",
		ntohs(iphdr->payload_len) + sizeof(struct ipv6hdr),
		sizeof(struct ipv6hdr));
	printf("source ip: %s\n", ipsrc);
	printf("destination ip: %s\n", ipdst);
	return (0);
}

int					get_ips(struct sockaddr_in *ipv4, struct sockaddr_in6 *ipv6,
	char *dev, char *prog)
{
	struct ifaddrs	*ifap = NULL;
	int				v4 = 0, v6 = 0, ret = 0;

	if (getifaddrs(&ifap) < 0)
	{
		dprintf(2, "%s: getifaddrs: %s\n", prog, strerror(errno));
		return (-1);
	}
	for (; ifap && (!v4 || !v6); ifap = ifap->ifa_next)
	{
		if (ifap->ifa_name && !strcmp(dev, ifap->ifa_name) && ifap->ifa_addr)
		{
			if (!v4 && ifap->ifa_addr->sa_family == AF_INET)
			{
				v4 = 1;
				memcpy((void *)ipv4, (void *)ifap->ifa_addr,
					sizeof(struct sockaddr_in));
			}
			else if (!v6 && ifap->ifa_addr->sa_family == AF_INET6)
			{
				v6 = 2;
				memcpy((void *)ipv6, (void *)ifap->ifa_addr,
					sizeof(struct sockaddr_in6));
			}
		}
	}
	freeifaddrs(ifap);
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
	return (0);
}

int					main(int argc, char **argv)
{
	struct iphdr		iphdr;
	struct ipv6hdr		ipv6hdr;
	pcap_t				*descr;
	int					type, ip;
	struct sockaddr_in	ipv4 = { 0 };
	struct sockaddr_in6	ipv6 = { 0 };
	u_char				packet[PACKET_SIZE_MAX];
	char				*dev, net[INET6_ADDRSTRLEN], mask[INET6_ADDRSTRLEN];
	char				ip4[INET6_ADDRSTRLEN] = { 0 },
						ip6[INET6_ADDRSTRLEN] = { 0 };
	bpf_u_int32			netp;

	printf("sizes:\n");
	printf("ether_header: %zu\n", sizeof(struct ether_header));
	printf("iphdr: %zu\n", sizeof(struct iphdr));
	printf("ipv6hdr: %zu\n", sizeof(struct ipv6hdr));
	printf("icmphdr: %zu\n", sizeof(struct icmphdr));
	printf("icmp6hdr: %zu\n", sizeof(struct icmp6hdr));
	printf("tcphdr: %zu\n", sizeof(struct tcphdr));
	printf("udphdr: %zu\n", sizeof(struct udphdr));
	printf("MAX_HEADER_SIZE: %zu\n", MAX_HEADER_SIZE);

	if (get_network(argv[0], &dev, net, mask, &netp))
		return (EXIT_FAILURE);
	printf("dev: %s\n", dev);
	printf("net: %s\n", net);
	printf("mask: %s\n", mask);

	if ((ip = get_ips(&ipv4, &ipv6, dev, argv[0])) < 0)
		return (EXIT_FAILURE);
	if (print_ips(ip, ip4, ip6, &ipv4, &ipv6, argv[0], dev))
		return (EXIT_FAILURE);

	if (!(descr = open_device(argv[0], dev)))
		return (EXIT_FAILURE);
	if (set_filter(descr, ip, ip4, ip6, argv[1], argv[0], netp))
		return (EXIT_FAILURE);
	if (grab_packet(argv[0], descr, packet))
		return (EXIT_FAILURE);
	if (print_ether_type(&type, packet))
		return (EXIT_FAILURE);
	if (type == ETHERTYPE_IP)
		parse_iphdr(&iphdr, packet, argv[0]);
	else if (type == ETHERTYPE_IPV6)
		parse_ipv6hdr(&ipv6hdr, packet, argv[0]);
	return (EXIT_SUCCESS);
}
