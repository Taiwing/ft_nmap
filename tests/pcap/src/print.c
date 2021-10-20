/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:08:28 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 14:57:20 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

static void		print_mac(u_char *ptr)
{
	for (int i = 0; i < ETHER_ADDR_LEN; ++i)
		printf("%02x%c", *ptr++, i < ETHER_ADDR_LEN - 1 ? ':' : '\n');
}

int			print_ether_type(int *type, u_char *packet)
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

void			print_tcphdr(struct tcphdr *tcph)
{
	printf("TCP header: (size = %zu)\n", sizeof(struct tcphdr));
	printf("source port: %d\n", ntohs(tcph->th_sport));
	printf("destination port: %d\n", ntohs(tcph->th_dport));
	printf("sequence: %d\n", ntohl(tcph->th_seq));
	printf("acknowledgment: %d\n", ntohl(tcph->th_ack));
	printf("data offset: %d\n", ntohs(tcph->th_off));
	printf("flags:");
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
	printf("\nwindow: %d\n", ntohs(tcph->th_win));
	printf("urgent pointer: %d\n", ntohs(tcph->th_urp));
	printf("sum: %#hx\n", tcph->th_sum);
}

int					print_ips(int ip, char *ip4, char *ip6,
	struct sockaddr_in *ipv4, struct sockaddr_in6 *ipv6, char *prog)
{
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
