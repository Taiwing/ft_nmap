/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/31 12:17:45 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/31 19:40:12 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void				set_packet_size(t_packet *packet)
{
	size_t	size;

	switch (packet->iphdr)
	{
		case E_IH_V4:
			size = ntohs(packet->ip->v4.tot_len);
			break;
		case E_IH_V6:
			size = ntohs(packet->ip->v6.payload_len) + sizeof(struct ipv6hdr);
			break;
		case E_IH_NONE:
			size = 0;
			break;
	}
	packet->size = size > RAW_DATA_MAXSIZE ? RAW_DATA_MAXSIZE : size;
}

static enum e_nexthdr	set_nexthdr(uint8_t type, enum e_iphdr iph)
{
	if (iph == E_IH_NONE)
		return (E_NH_NONE);
	else if (type == IP_HEADER_UDP)
		return (E_NH_UDP);
	else if (type == IP_HEADER_TCP)
		return (E_NH_TCP);
	else if (type == IP_HEADER_ICMP && iph == E_IH_V4)
		return (E_NH_ICMP);
	else if (type == IP_HEADER_ICMP6 && iph == E_IH_V6)
		return (E_NH_ICMP6);
	return (E_IH_NONE);
}

void					reset_packet(t_packet *packet, uint8_t *datap)
{
	packet->iphdr = packet->nextiphdr = E_IH_NONE;
	packet->nexthdr = packet->lasthdr = E_NH_NONE;
	packet->ip = packet->nextip = NULL;
	packet->next = packet->last = NULL;
	packet->size = 0;
	packet->raw_data = datap ? datap : packet->buf;
}

void					init_packet(t_packet *packet,
		enum e_iphdr iph, uint8_t *datap)
{
	uint8_t	type;

	reset_packet(packet, datap);
	if ((packet->iphdr = iph) == E_IH_NONE)
		return;
	packet->ip = (t_iphdr *)packet->raw_data;
	type = iph == E_IH_V4 ? packet->ip->v4.protocol : packet->ip->v6.nexthdr;
	if ((packet->nexthdr = set_nexthdr(type, iph)) == E_NH_NONE)
		return (set_packet_size(packet));
	packet->next = (t_nexthdr *)(packet->raw_data + (iph == E_IH_V4
		? sizeof(struct iphdr) : sizeof(struct ipv6hdr)));
	if (packet->nexthdr == E_NH_TCP || packet->nexthdr == E_NH_UDP)
		return (set_packet_size(packet));
	packet->nextiphdr = iph;
	packet->nextip = (t_iphdr *)((uint8_t *)packet->next
		+ (packet->nexthdr == E_NH_ICMP ? sizeof(struct icmphdr)
		: sizeof(struct icmp6hdr)));
	type = iph == E_IH_V4 ? packet->nextip->v4.protocol
		: packet->nextip->v6.nexthdr;
	if ((packet->lasthdr = set_nexthdr(type, iph)) != E_NH_NONE)
		packet->last = (t_nexthdr *)((uint8_t *)packet->nextip + (iph == E_IH_V4
			? sizeof(struct iphdr) : sizeof(struct ipv6hdr)));
	set_packet_size(packet);
}
