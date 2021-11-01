/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/31 12:17:45 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/01 11:31:09 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void				set_packet_size(t_packet *packet)
{
	size_t			size = 0;
	enum e_iphdr	iphdr[2] = { packet->iphdr, packet->nextiphdr };
	enum e_nexthdr	nexthdr[2] = { packet->nexthdr, packet->lasthdr };

	for (int i = 0; i < 2; ++i)
	{
		switch (iphdr[i])
		{
			case E_IH_V4: size += sizeof(struct iphdr);			break;
			case E_IH_V6: size += sizeof(struct ipv6hdr);		break;
			case E_IH_NONE: size += 0;							break;
		}
	}
	for (int i = 0; i < 2; ++i)
	{
		switch (nexthdr[i])
		{
			case E_NH_ICMP: size += sizeof(struct icmphdr);		break;
			case E_NH_ICMP6: size += sizeof(struct icmp6hdr);	break;
			case E_NH_TCP: size += sizeof(struct tcphdr);		break;
			case E_NH_UDP: size += sizeof(struct udphdr);		break;
			case E_NH_NONE: size += 0;							break;
		}
	}
	packet->size = size;
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

void					reset_packet(t_packet *packet)
{
	packet->iphdr = packet->nextiphdr = E_IH_NONE;
	packet->nexthdr = packet->lasthdr = E_NH_NONE;
	packet->ip = packet->nextip = NULL;
	packet->next = packet->last = NULL;
	packet->size = 0;
}

void					init_packet(t_packet *packet, enum e_iphdr iph)
{
	uint8_t	type;

	reset_packet(packet);
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
		packet->last = (t_nexthdr *)(packet->nextip + (iph == E_IH_V4
			? sizeof(struct iphdr) : sizeof(struct ipv6hdr)));
	set_packet_size(packet);
}
