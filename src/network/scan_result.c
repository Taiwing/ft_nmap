/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_result.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/31 21:04:12 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 08:28:34 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static uint8_t	scan_syn_res(t_packet *reply)
{
	uint8_t	result;

	result = E_STATE_FILTERED;
	if (reply->nexthdr == E_NH_TCP)
	{
		if (reply->next->tcp.th_flags & TH_SYN)
			result = E_STATE_OPEN;
		else if (reply->next->tcp.th_flags & TH_RST)
			result = E_STATE_CLOSED;
	}
	return (result);
}

static uint8_t	scan_udp_res(t_packet *reply)
{
	uint8_t	result;

	result = E_STATE_FILTERED;
	if (reply->iphdr == E_IH_NONE)
		result |= E_STATE_OPEN;
	else if (reply->nexthdr == E_NH_UDP)
		result = E_STATE_OPEN;
	else if ((reply->nexthdr == E_NH_ICMP
		&& reply->next->icmp.type == ICMP_DEST_UNREACH
		&& reply->next->icmp.code == ICMP_PORT_UNREACH))
		result = E_STATE_CLOSED;
	else if ((reply->nexthdr == E_NH_ICMP6
		&& reply->next->icmp6.icmp6_type == ICMPV6_DEST_UNREACH
		&& reply->next->icmp6.icmp6_code == ICMPV6_PORT_UNREACH))
		result = E_STATE_CLOSED;
	return (result);
}

static uint8_t	scan_ack_res(t_packet *reply)
{
	uint8_t	result;

	result = E_STATE_FILTERED;
	if (reply->nexthdr == E_NH_TCP && reply->next->tcp.th_flags & TH_RST)
		result = E_STATE_UNFILTERED;
	return (result);
}

static uint8_t	scan_nfx_res(t_packet *reply)
{
	uint8_t	result;

	result = E_STATE_FILTERED;
	if (reply->iphdr == E_IH_NONE)
		result |= E_STATE_OPEN;
	else if (reply->nexthdr == E_NH_TCP && reply->next->tcp.th_flags & TH_RST)
		result = E_STATE_CLOSED;
	return (result);
}

void			set_scan_result(t_scan_job *scan, t_packet *reply)
{
	switch (scan->type)
	{
		case E_SYN: scan->result = scan_syn_res(reply);				break;
		case E_UDP: scan->result = scan_udp_res(reply);				break;
		case E_ACK: scan->result = scan_ack_res(reply);				break;
		case E_NULL:
		case E_FIN:
		case E_XMAS: scan->result = scan_nfx_res(reply);			break;
	}
}
