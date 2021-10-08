/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/05 05:03:01 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/08 07:56:11 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>

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

static const u_char	*grab_packet(char *prog, pcap_t *descr)
{
	struct pcap_pkthdr		hdr;
	struct ether_header		*eptr;
	const u_char			*packet;
	char					errbuf[PCAP_ERRBUF_SIZE];

	if (!(packet = pcap_next(descr, &hdr)))
	{
		dprintf(2, "%s: pcap_next: did not grab packet :(\n", prog);
		return (NULL);
	}
	printf("Grabbed packet of length %d\n", hdr.len);
	printf("Received at .... %s\n", ctime((const time_t *)&hdr.ts.tv_sec));
	printf("Ethernet address length is %d\n", ETHER_HDR_LEN);
	return (packet);
}

static void			print_mac(u_char *ptr)
{
	for (int i = 0; i < ETHER_ADDR_LEN; ++i)
		printf("%02x%c", *ptr++, i < ETHER_ADDR_LEN - 1 ? ':' : '\n');
}

static int			print_ether_type(const u_char *packet)
{
	struct ether_header	*eptr = (struct ether_header *)packet;
	int type = ntohs(eptr->ether_type);

	printf("Ethernet type hex:%x dec:%d %s\n", type, type,
		type == ETHERTYPE_IP ? "is an IP packet" :
		type == ETHERTYPE_ARP ? "is an ARP packet" :
		"not IP");
	printf("Destination Address: ");
	print_mac((u_char *)eptr->ether_dhost);
	printf("Source Address: ");
	print_mac((u_char *)eptr->ether_shost);
	return (type == ETHERTYPE_IP || type == ETHERTYPE_ARP);
}


int					main(int argc, char **argv)
{
	int				ret;
	pcap_t			*descr;
	const u_char	*packet;
	char			*dev, net[INET6_ADDRSTRLEN], mask[INET6_ADDRSTRLEN];

	if ((ret = get_network(argv[0], &dev, net, mask)))
		return (ret);
	printf("dev: %s\n", dev);
	printf("net: %s\n", net);
	printf("mask: %s\n", mask);

	if (!(descr = open_device(argv[0], dev)))
		return (EXIT_FAILURE);
	if (!(packet = grab_packet(argv[0], descr)))
		return (EXIT_FAILURE);
	if (print_ether_type(packet))
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
