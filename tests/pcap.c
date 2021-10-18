/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/05 05:03:01 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/18 07:57:45 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

static int			get_network(char *prog, char **dev, char *net, char *mask)
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
	return (EXIT_SUCCESS);
}

static pcap_t		*open_device(char *prog, char *dev)
{
	pcap_t	*descr;
	char	errbuf[PCAP_ERRBUF_SIZE];

	if (!(descr = pcap_open_live(dev, BUFSIZ, 1, 1000000, errbuf)))
		dprintf(2, "%s: pcap_open_live: %s\n", prog, errbuf);
	return (descr);
}

static void	phandler(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{
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

	if ((ret = pcap_dispatch(descr, 1, phandler, buf)) == PCAP_ERROR)
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
	printf("Grabbed packet of length %d\n", h->len);
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
		*type == ETHERTYPE_ARP ? "is an ARP packet" :
		"not IP");
	printf("Destination Address: ");
	print_mac((u_char *)eptr->ether_dhost);
	printf("Source Address: ");
	print_mac((u_char *)eptr->ether_shost);
	return (*type != ETHERTYPE_IP && *type != ETHERTYPE_ARP);
}

int					parse_iphdr(struct ip *iphdr, u_char *packet, char *prog)
{
	int		type;
	char	ipsrc[INET6_ADDRSTRLEN + 1] = { 0 };
	char	ipdst[INET6_ADDRSTRLEN + 1] = { 0 };

	memcpy((void *)iphdr, (void *)(packet + sizeof(struct ether_header)),
		sizeof(struct ip));
	type = iphdr->ip_v == 4 ? AF_INET : AF_INET6;
	if (!inet_ntop(type, (void *)&iphdr->ip_src.s_addr, ipsrc, INET6_ADDRSTRLEN))
	{
		dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
		return (1);
	}
	if (!inet_ntop(type, (void *)&iphdr->ip_dst.s_addr, ipdst, INET6_ADDRSTRLEN))
	{
		dprintf(2, "%s: inet_ntop: %s\n", prog, strerror(errno));
		return (1);
	}
	printf("IP packet: (len = %hu, iphdr_size = %zu)\n", ntohs(iphdr->ip_len),
		sizeof(struct ip));
	printf("source ip: %s\n", ipsrc);
	printf("destination ip: %s\n", ipdst);
	return (0);
}

int					main(int argc, char **argv)
{
	struct ip		iphdr;
	pcap_t			*descr;
	int				ret, type;
	u_char			packet[PACKET_SIZE_MAX];
	char			*dev, net[INET6_ADDRSTRLEN], mask[INET6_ADDRSTRLEN];

	if ((ret = get_network(argv[0], &dev, net, mask)))
		return (ret);
	printf("dev: %s\n", dev);
	printf("net: %s\n", net);
	printf("mask: %s\n", mask);

	if (!(descr = open_device(argv[0], dev)))
		return (EXIT_FAILURE);
	if (grab_packet(argv[0], descr, packet))
		return (EXIT_FAILURE);
	if (print_ether_type(&type, packet))
		return (EXIT_FAILURE);
	if (type == ETHERTYPE_IP)
		parse_iphdr(&iphdr, packet, argv[0]);
	return (EXIT_SUCCESS);
}
