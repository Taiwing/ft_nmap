/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   layer4_headers.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:47:10 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/29 18:52:52 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "network.h"

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
	else if (ip6h)
		sum += sum_bit16((uint16_t *)&ip6h->saddr, sizeof(struct in6_addr) * 2);
	sum += htons(len) + htons(ip4h ? ip4h->protocol : ip6h->nexthdr)
		+ sum_bit16((uint16_t *)packet, len);
	return (checksum((uint16_t *)&sum, sizeof(uint64_t)));
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
	ft_bzero(udp_packet, sizeof(struct udphdr));
	udph->uh_sport = htons(srcp);
	udph->uh_dport = htons(dstp);
	udph->uh_ulen = htons(udplen);
	udph->uh_sum = transport_checksum(version, iphdr, udp_packet, udplen);
	return (0);
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
int			init_tcp_header(uint8_t *tcp_packet, t_tcph_args *args)
{
	struct tcphdr	*tcph = (struct tcphdr *)tcp_packet;
	struct iphdr	*ip4h = args->version == 4 ? args->iphdr : NULL;
	struct ipv6hdr	*ip6h = args->version == 6 ? args->iphdr : NULL;
	uint16_t		tcplen = ip6h ? ntohs(ip6h->payload_len)
						: ip4h ? ntohs(ip4h->tot_len) : 0;

	if (ip4h)
		tcplen = tcplen > sizeof(struct iphdr)
			? tcplen - sizeof(struct iphdr) : 0;
	if ((!ip4h && !ip6h) || tcplen < sizeof(struct tcphdr))
		return (-1);
	ft_bzero(tcp_packet, sizeof(struct tcphdr));
	tcph->th_sport = htons(args->srcp);
	tcph->th_dport = htons(args->dstp);
	tcph->th_seq = htonl(args->seq);
	tcph->th_ack = htonl(args->ack);
	tcph->th_off = sizeof(struct tcphdr) / sizeof(uint32_t);
	tcph->th_flags = args->flags;
	tcph->th_win = htons(args->win);
	tcph->th_urp = htons(args->urp);
	tcph->th_sum = transport_checksum(args->version, args->iphdr,
		tcp_packet, tcplen);
	return (0);
}
