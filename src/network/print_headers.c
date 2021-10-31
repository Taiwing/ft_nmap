/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_headers.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:08:28 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/31 15:09:34 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "network.h"

static void		print_mac(uint8_t *ptr)
{
	for (int i = 0; i < ETHER_ADDR_LEN; ++i)
		ft_printf("%02x%c", *ptr++, i < ETHER_ADDR_LEN - 1 ? ':' : '\n');
}

int			print_ether_type(uint8_t *packet)
{
	struct ether_header	*eptr = (struct ether_header *)packet;
	int					type = ntohs(eptr->ether_type);

	ft_printf("Ethernet type hex:%x dec:%d %s\n", type, type,
		type == ETHERTYPE_IP ? "is an IP packet" :
		type == ETHERTYPE_IPV6 ? "is an IPv6 packet" :
		type == ETHERTYPE_ARP ? "is an ARP packet" :
		"not IP");
	ft_printf("Destination Address: ");
	print_mac((uint8_t *)eptr->ether_dhost);
	ft_printf("Source Address: ");
	print_mac((uint8_t *)eptr->ether_shost);
	return (type != ETHERTYPE_IP
			&& type != ETHERTYPE_IPV6
			&& type != ETHERTYPE_ARP);
}

int					print_iphdr(void *iphdr, int domain, char *exec)
{
	void			*sptr, *dptr;
	char			ipsrc[INET6_ADDRSTRLEN + 1] = { 0 };
	char			ipdst[INET6_ADDRSTRLEN + 1] = { 0 };
	struct iphdr	*ip4h = domain == AF_INET ? iphdr : NULL;
	struct ipv6hdr	*ip6h = domain == AF_INET6 ? iphdr : NULL;

	if (!ip4h && !ip6h)
		return (!!ft_dprintf(2, "%s: %s: invalid domain '%d'\n",
			exec, __func__, domain));
	sptr = ip4h ? (void *)&ip4h->saddr : (void *)&ip6h->saddr;
	dptr = ip4h ? (void *)&ip4h->daddr : (void *)&ip6h->daddr;
	if (!inet_ntop(domain, sptr, ipsrc, INET6_ADDRSTRLEN))
		return (!!ft_dprintf(2, "%s: inet_ntop: %s\n", exec, strerror(errno)));
	if (!inet_ntop(domain, dptr, ipdst, INET6_ADDRSTRLEN))
		return (!!ft_dprintf(2, "%s: inet_ntop: %s\n", exec, strerror(errno)));
	ft_printf("IPv%d header: (size = %zu)\n\t%s: %d\n\t%s: %hhu\n\t%s: %hhu\n",
		ip4h ? 4 : 6, ip4h ? sizeof(struct iphdr): sizeof(struct ipv6hdr),
		ip4h ? "tot_len" : "payload_len", ip4h ? ntohs(ip4h->tot_len) :
		ntohs(ip6h->payload_len), ip4h ? "ttl" : "hop_limit", ip4h ? ip4h->ttl
		: ip6h->hop_limit, ip4h ? "protocol" : "nexthdr", ip4h ? ip4h->protocol
		: ip6h->nexthdr);
	ft_printf("\tsource ip: %s\n\tdestination ip: %s\n", ipsrc, ipdst);
	return (0);
}

void			print_udphdr(struct udphdr *udph)
{
	ft_printf("UDP header: (size = %zu)\n", sizeof(struct udphdr));
	ft_printf("\tsource port: %d\n", ntohs(udph->uh_sport));
	ft_printf("\tdestination port: %d\n", ntohs(udph->uh_dport));
	ft_printf("\tlen: %d\n", ntohs(udph->uh_ulen));
	ft_printf("\tsum: %#hx\n", udph->uh_sum);
}

void			print_tcphdr(struct tcphdr *tcph)
{
	ft_printf("TCP header: (size = %zu)\n", sizeof(struct tcphdr));
	ft_printf("\tsource port: %d\n", ntohs(tcph->th_sport));
	ft_printf("\tdestination port: %d\n", ntohs(tcph->th_dport));
	ft_printf("\tsequence: %d\n", ntohl(tcph->th_seq));
	ft_printf("\tacknowledgment: %d\n", ntohl(tcph->th_ack));
	ft_printf("\tdata offset: %d\n", ntohs(tcph->th_off));
	ft_printf("\tflags:");
	if (!tcph->th_flags)
		ft_printf(" 0");
	if (tcph->th_flags & TH_FIN)
		ft_printf(" FIN");
	if (tcph->th_flags & TH_SYN)
		ft_printf(" SYN");
	if (tcph->th_flags & TH_RST)
		ft_printf(" RST");
	if (tcph->th_flags & TH_PUSH)
		ft_printf(" PSH");
	if (tcph->th_flags & TH_ACK)
		ft_printf(" ACK");
	if (tcph->th_flags & TH_URG)
		ft_printf(" URG");
	ft_printf("\n\twindow: %d\n", ntohs(tcph->th_win));
	ft_printf("\turgent pointer: %d\n", ntohs(tcph->th_urp));
	ft_printf("\tsum: %#hx\n", tcph->th_sum);
}

int					print_nexthdr(void *iphdr, int domain,
						uint16_t size, char *exec)
{
	struct iphdr	*ip4h = domain == AF_INET ? iphdr : NULL;
	struct ipv6hdr	*ip6h = domain == AF_INET6 ? iphdr : NULL;
	int				type = ip4h ? ip4h->protocol : ip6h ? ip6h->nexthdr : 0;
	void			*nexthdr = iphdr + (ip4h ? sizeof(struct iphdr)
		: ip6h ? sizeof(struct ipv6hdr) : 0);
	uint16_t		nexthdr_size = type == IP_HEADER_ICMP ?
		(ip4h ? sizeof(struct icmphdr) : sizeof (struct icmp6hdr)) :
		type == IP_HEADER_TCP ? sizeof(struct tcphdr) :
		type == IP_HEADER_UDP ? sizeof(struct udphdr) : 0;

	if (!ip4h && !ip6h)
		return (!!ft_dprintf(2, "%s: %s: invalid domain '%d'\n",
			exec, __func__, domain));
	if (size < nexthdr_size)
		return (!!ft_dprintf(2, "%s: %s: not enough data for next header '%d'\n",
			exec, __func__, type));
	size -= nexthdr_size;
	if (type == IP_HEADER_ICMP)
		return (print_icmphdr(nexthdr, domain, size, exec));
	else if (type == IP_HEADER_TCP)
		print_tcphdr((struct tcphdr *)nexthdr);
	else if (type == IP_HEADER_UDP)
		print_udphdr((struct udphdr *)nexthdr);
	if (size)
		ft_printf("\tdata: %hu bytes\n", size);
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
		return (!!ft_dprintf(2, "%s: %s: invalid domain '%d'\n",
			exec, __func__, domain));
	ft_printf("ICMP%s header: (size = %zu)\n", ip4h ? "" : "v6",
		ip4h ? sizeof(struct icmphdr) : sizeof(struct icmp6hdr));
	ft_printf("\ttype: %hhu\n", ptr->type);
	ft_printf("\tcode: %hhu\n", ptr->code);
	ft_printf("\tchecksum: %#hx\n", ptr->checksum);
	if ((ip4h && size < sizeof(struct iphdr))
		|| (ip6h && size < sizeof(struct ipv6hdr)))
		return (!ft_printf("\tdata: %hu bytes\n", size));
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
		return (!!ft_dprintf(2, "%s: packet is too small for an IP header\n",
			__func__));
	if (print_iphdr(packet, domain, exec))
		return (1);
	size -= iphdr_size;
	return (print_nexthdr(packet, domain, size, exec));
}
